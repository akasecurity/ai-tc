import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { readControlPlaneCredentialState } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { throttled } from '@akasecurity/plugin-sdk';
import { isAttached, isHistorySyncConsentValid } from '@akasecurity/schema';

/**
 * The marker that paces the history drain.
 *
 * DISTINCT FROM EVERY OTHER JOB'S. A marker name is the gate's identity, so two
 * jobs sharing one would starve each other: whichever ran first would suppress
 * the other for the whole window, and neither would be visibly wrong.
 */
export const HISTORY_SYNC_MARKER_NAME = 'history-sync-last-attempt';

/**
 * The filename this module resolves as a sibling of the running script.
 *
 * EXPORTED so the one place that emits it and the one place that probes for it
 * read the same string. A build test declaring its own copy would prove the two
 * copies agree and nothing else.
 */
export const HISTORY_SYNC_SCRIPT_NAME = 'history-sync.js';

/**
 * How long one pass suppresses the next.
 *
 * Shorter than the policy pull's window because this job has an END: it is
 * draining a finite backlog, and a machine with a large one should get through
 * it in days rather than weeks. Once the backlog is empty the passes are cheap —
 * one query that finds nothing.
 */
export const HISTORY_SYNC_THROTTLE_MS = 5 * 60 * 1000;

export interface HistorySyncTriggerDeps {
  /** Where the detached child lives. Injectable because the shipped layout differs from the source tree. */
  scriptUrl?: URL;
  spawnChild?: (scriptPath: string) => void;
  isThrottled?: (dataDir: string) => boolean;
}

/**
 * Drain already-recorded activity in a DETACHED CHILD, at most every five
 * minutes, and never on the path a user is waiting on.
 *
 * SYNCHRONOUS AND `void`, deliberately. Hook entries exit as soon as their work
 * is done, so an un-awaited promise here would be killed mid-flight and a
 * returned one would be a promise nobody can await. Every request therefore
 * happens in a child that outlives this process.
 *
 * NEVER THROWS. It runs inside SessionStart, where a failure must cost a pass
 * and never a session.
 *
 * THE GRANT IS CHECKED HERE, not only in the child. A machine whose user never
 * consented must not pay a process spawn to discover that, and — more to the
 * point — must not write the throttle marker either, which is a file appearing
 * on disk because of a feature that is off.
 *
 * ATTACHED FIRST, THROTTLE LAST. Without that ordering every unattached machine
 * forks a child every five minutes for the life of the install, and "unattached"
 * is the state of almost every machine.
 *
 * THE THROTTLE'S VERDICT IS OBEYED, with no exception for "there is still work
 * to do". An unfinished backlog is the normal state of this job, so a bypass
 * conditioned on it would fork a child on EVERY session until the drain
 * completed — and on a machine that cannot reach its deployment, for ever.
 */
export function triggerHistorySync(config: PluginConfig, deps: HistorySyncTriggerDeps = {}): void {
  try {
    if (!isAttached(config.settings)) return;
    const connection = config.settings.controlPlane;
    if (connection === undefined) return;
    if (!isHistorySyncConsentValid(config.settings.historySyncConsent, connection.endpoint)) return;
    // A credential that is absent, untrusted or minted for another deployment
    // means there is nothing to send to — and the child would only rediscover
    // that after paying a process spawn.
    if (!readControlPlaneCredentialState(config.settingsDir, connection).usable) return;

    const isThrottled =
      deps.isThrottled ??
      ((dir: string) => throttled(dir, HISTORY_SYNC_MARKER_NAME, HISTORY_SYNC_THROTTLE_MS));
    if (isThrottled(config.dataDir)) return;

    const scriptPath = fileURLToPath(
      deps.scriptUrl ?? new URL(HISTORY_SYNC_SCRIPT_NAME, import.meta.url),
    );
    (deps.spawnChild ?? spawnDetached)(scriptPath);
  } catch {
    // A drain that cannot be started is a slower backfill, not a broken session.
  }
}

/**
 * `detached` + `unref()` is what lets the child outlive an entry that is about
 * to exit; without the `unref()` the parent would wait on it, which is the
 * opposite of the intent.
 */
function spawnDetached(scriptPath: string): void {
  const child = spawn(process.execPath, [scriptPath], { detached: true, stdio: 'ignore' });
  // MANDATORY, not defensive. libuv reports fork failures (EAGAIN under
  // process-table pressure, EMFILE on fd exhaustion, EACCES, ENOENT) by emitting
  // 'error' on a LATER TICK rather than by throwing — and an unhandled 'error'
  // on an EventEmitter is rethrown as an uncaughtException. By then the
  // try/catch above has returned, so it cannot see it, and SessionStart dies
  // mid-flight instead of degrading.
  child.on('error', () => {
    // Nothing to do about a failed background spawn; the next session retries,
    // and the outcome surfaces through status as progress that did not move.
  });
  child.unref();
}
