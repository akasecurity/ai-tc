import type { StorePosturePlugin, StorePostureSnapshot } from '@akasecurity/schema';

import type { StoreReadout } from './posture-snapshot.ts';
import type { PostureStore } from './posture-store.ts';
import { REQUEST_TIMEOUT_MS, withTimeout } from './with-timeout.ts';

export const POSTURE_REPORT_INTERVAL_MS = 60 * 60 * 1000;

export interface PostureReporterDeps {
  report(snapshot: StorePostureSnapshot): Promise<unknown>; // client.reportStorePosture
  store: PostureStore;
  readStore(): StoreReadout; // () => readStorePosture(config.dbPath)
  hostname(): string; // os.hostname
  now(): number; // Date.now
  /**
   * The reporting plugin's identity and policy freshness, or `undefined` when
   * this build does not know it (an OSS-shaped caller, or a test).
   *
   * Async because two of the five members come from the policy CACHE, which is
   * read from disk. Optional because the block itself is `.optional()` on the
   * wire — B4 shipped the transport and the column; until E2 there was simply no
   * producer, so every report a shipped build sent carried no `plugin` at all.
   *
   * Fail-open like everything else here: a producer that throws costs the block,
   * never the snapshot. The rest of the posture — `storePresent` above all, the
   * wipe/tamper signal — is worth strictly more than the plugin metadata.
   */
  pluginBlock?(): Promise<StorePosturePlugin | undefined>;
}

export interface PostureReporter {
  /**
   * Phase 1: throttle check, attempt stamp, and the store read — everything
   * LOCAL. Returns the snapshot to send, or null when throttled, unreadable,
   * or failed. This phase contains the blocking, un-preemptible node:sqlite
   * scan (see posture-snapshot.ts), which is why it is split from the send:
   * the caller must run it only while NO withTimeout timer is armed — a timer
   * counting through the block wins races it should have lost — and never
   * ahead of a functional call whose result the session needs. The attached
   * gateway runs it strictly after its inventory call has settled (see the
   * ordering rationale on AttachedDataGateway.ensureInventory).
   *
   * The scan is the only unbounded part BY NECESSITY — withTimeout cannot
   * preempt synchronous work. The store's async fs I/O (state read, attempt
   * stamp) has no such excuse: a stalled NFS/FUSE mount or a permission
   * prompt would otherwise hang this promise forever, with the harness's 10s
   * SessionStart kill as the only backstop. Both fs calls are individually
   * bounded at REQUEST_TIMEOUT_MS below, same as the old pre-split
   * maybeReportPosture call was.
   */
  prepare(): Promise<StorePostureSnapshot | null>;
  /** Phase 2: the network send of a prepared snapshot. Fail-open: any error is silence. */
  send(snapshot: StorePostureSnapshot): Promise<void>;
}

/**
 * Throttled posture self-report. Fail-open discipline: any error is silence.
 *
 * The throttle advances on ATTEMPT, not on success. It reads as the more
 * forgiving choice to retry a failed send next session instead of waiting out
 * the interval, but this stamp does not only gate the network call — it gates
 * `readStore()`, a blocking, un-preemptible SQLite scan that `withTimeout`
 * cannot interrupt and whose only real backstop is the harness's 10s
 * SessionStart hook kill. Advancing on success alone meant that against an
 * unreachable control plane the stamp never moved and that scan was re-paid on EVERY
 * SessionStart — measured at 5 reads per 5 sessions inside one interval, in
 * precisely the outage the "at most once an hour" comments were reassuring
 * about. Bounding the expensive local work matters more than a prompt retry of
 * a send the control plane is not there to receive; a device that misses an hour
 * still lands far inside the control plane's freshness window.
 */
export function createPostureReporter(deps: PostureReporterDeps): PostureReporter {
  async function prepare(): Promise<StorePostureSnapshot | null> {
    try {
      const state = await withTimeout(deps.store.read(), REQUEST_TIMEOUT_MS);
      // null: no identity could be established this attempt — a fresh mint
      // whose persist failed (see posture-store.ts), rather than something
      // safe to report under and lose track of again next session.
      if (state === null) return null;
      const nowMs = deps.now();
      // `elapsed >= 0` guards a lastAttemptedAtMs in the FUTURE. A clock that
      // jumps ahead (bad NTP, VM snapshot restore, manual date fix) and is then
      // corrected backwards leaves a negative delta, which is permanently
      // < the interval — the device would never report again until wall-clock
      // caught up, while the control plane graded it `silent`, the alarm state, with
      // no local way to recover. A future stamp is treated as due now.
      const elapsed = nowMs - state.lastAttemptedAtMs;
      if (elapsed >= 0 && elapsed < POSTURE_REPORT_INTERVAL_MS) return null;
      // Advance BEFORE the expensive read, so every path below this line —
      // readError, a rejected send, a thrown client — costs one scan per
      // interval rather than one per session.
      //
      // Best-effort: persisting the stamp is a file write, and this is now on
      // the path to reporting at all. If its failure propagated, an unwritable
      // ~/.aka/settings would suppress the report entirely — strictly worse
      // than the unthrottled reads this exists to prevent. A device that cannot
      // persist the stamp degrades to the old every-session behaviour, which is
      // the correct direction to fail.
      try {
        await withTimeout(deps.store.markAttempted(state.deviceId, nowMs), REQUEST_TIMEOUT_MS);
      } catch {
        // throttle is advisory; never let it gate the report
      }
      // `readError` is a "could not measure", not a measurement — reporting the
      // zeroed literal that accompanies it would assert a healthy device has no
      // store. Send nothing; sustained unreadability then surfaces as `silent`
      // on its own, which is the honest signal.
      const { readError, ...measurement } = deps.readStore();
      if (readError) return null;
      // Built AFTER the store read, and never allowed to cost it: a failure here
      // drops the plugin block and still reports posture.
      let plugin: StorePosturePlugin | undefined;
      try {
        plugin = await deps.pluginBlock?.();
      } catch {
        plugin = undefined;
      }
      return {
        deviceId: state.deviceId,
        hostname: deps.hostname(),
        capturedAt: nowMs,
        ...measurement,
        // Omit the key rather than spread an explicit `undefined` —
        // exactOptionalPropertyTypes distinguishes the two, and the bridge in
        // factory.ts keys on presence.
        ...(plugin === undefined ? {} : { plugin }),
      };
    } catch {
      // fail-open: posture is telemetry; the session must never notice
      return null;
    }
  }

  async function send(snapshot: StorePostureSnapshot): Promise<void> {
    try {
      await deps.report(snapshot);
    } catch {
      // fail-open: posture is telemetry; the session must never notice
    }
  }

  return { prepare, send };
}
