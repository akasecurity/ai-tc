import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { ATTACHED_FORWARD_STATE_FILENAME } from '@akasecurity/persistence';
import { DATA_FILE_MODE, ensureDataDir } from '@akasecurity/plugin-sdk';

import { classifyFailure, type ControlPlaneFailure, statusOf } from './failure.ts';
import { withTimeout } from './with-timeout.ts';

/**
 * Whether an error is this machine refusing to SEND, rather than a control
 * plane refusing to accept.
 *
 * Read STRUCTURALLY off the error's `name`, never with `instanceof`, for the
 * reason `statusOf` gives in ./failure.ts: this code is bundled into every hook
 * script while the transport is a separate package, and a prototype identity
 * that survives one bundler configuration is not a thing to hang a breaker
 * decision on.
 */
function isInvalidRequest(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { name?: unknown }).name === 'RemoteRequestInvalid'
  );
}

/**
 * A 404 on a route this build knows — the deployment predates it.
 *
 * Matched on `name` rather than `instanceof`, exactly as above: this module
 * classifies whatever the injected client throws, and a fake in a test is not
 * required to be an instance of anything.
 */
function isRouteAbsent(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { name?: unknown }).name === 'RemoteRouteAbsent'
  );
}

/**
 * A 4xx from the DEPLOYMENT that says "you answered, and refused this BODY" —
 * never "you are down" (a 5xx, a timeout, a 429) or "this credential is no
 * good" (401/403).
 *
 * A 400/413/422 is what a schema mismatch between a device build and a
 * deployment build produces from the SERVER side, the same way a stale build
 * produces `invalid-request` on the client's own side — reachable for the same
 * reason `route-absent` is. 404 is excluded because that status already has
 * its own, more specific meaning on this route.
 *
 * 429 is excluded DELIBERATELY, and for a narrower reason than it looks: a
 * `rejected` verdict DOES count toward the breaker now (see `recordFailure`),
 * so the risk is not that a sustained 429 goes uncounted — it is
 * `forwardBatch`'s per-item pass, which every `rejected` chunk still enters.
 * Isolating one row makes sense against a genuine body-shape defect; against a
 * rate limit it is the opposite of the remedy, firing up to 50 more requests
 * at the SAME already-throttled endpoint with no pacing between them before
 * the third chunk finally opens the breaker. That is precisely the burst
 * `forwardBatch`'s own docblock says stays serial to avoid: "the plane's
 * per-key rate limiting answers with the refusals the breaker THEN COUNTS." A
 * 429 is retriable, not malformed — it belongs with `unreachable`, which
 * counts it without ever retrying a whole chunk item by item.
 *
 * Read the same way `statusOf` reads every other status: structurally, off
 * whatever the transport raised, never by class identity.
 */
function isServerRejection(err: unknown): boolean {
  const status = statusOf(err);
  return (
    status !== null &&
    status >= 400 &&
    status <= 499 &&
    status !== 401 &&
    status !== 403 &&
    status !== 404 &&
    status !== 429
  );
}

/**
 * The general forward budget. Looser than the decision-path bound below
 * because these forwards sit behind a local write that has already succeeded —
 * the caller's result is in hand, and this is the organization's copy catching up.
 */
export const FORWARD_BUDGET_MS = 1500;

/**
 * The budget for a forward on the DECISION path — anything a hook is blocked
 * on while a user waits. Tighter than FORWARD_BUDGET_MS on purpose: a slow
 * control plane may cost the organization's copy of an event, but it must
 * never be felt as latency in the session.
 */
export const DECISION_PATH_BUDGET_MS = 800;

/** Consecutive failures that trip the breaker open. */
export const BREAKER_FAILURE_THRESHOLD = 3;

/**
 * How long the breaker stays open before a single probe is allowed through.
 * Sized against hook cadence rather than a server's recovery time: the point
 * is that a session's worth of hooks after a control plane goes down pays the
 * timeout once, not once per hook.
 */
export const BREAKER_COOLDOWN_MS = 30_000;

/**
 * Cross-process breaker state.
 *
 * This file records BREAKER BOOKKEEPING ONLY — a failure count, the instant the
 * breaker opened, and a three-member enum naming HOW the last attempt failed. It
 * never holds a payload and never holds a credential, and that is still true
 * even though a failed forward is now RETAINED rather than dropped. The retention
 * is a `synced_at` column left NULL on a row the local store already holds; this
 * file gains nothing to hold, because the knowledge that forwarding is currently
 * pointless is all it ever needed to carry across processes.
 *
 * `lastFailure` is bounded by the same rule and is why it is an enum rather than
 * an error string. A message from a failed request can carry the URL, a header
 * echo, or a fragment of the body that was being sent — and the body on this
 * path IS the event content. The only way to be sure none of that is ever
 * written next to a session's telemetry is to have nothing to redact, so the
 * classification happens in memory and the classification alone is stored (same
 * argument sync-state.ts makes for its own outcome).
 */
interface BreakerState {
  consecutiveFailures: number;
  /** Epoch ms the breaker opened, or null when closed. */
  openedAtMs: number | null;
  /**
   * How the most recent failure failed, or null when nothing has failed since
   * the last success. Carried across half-open probes — a probe re-stamps the
   * breaker but does not re-diagnose it, and a 403 that was refused an hour ago
   * is still the reason this device is silent.
   */
  lastFailure: ControlPlaneFailure | null;
}

const CLOSED: BreakerState = { consecutiveFailures: 0, openedAtMs: null, lastFailure: null };

/**
 * Validated on the way in, exactly as `sync-state.ts` validates its own outcome:
 * `lastFailure` is RENDERED, so an arbitrary string from a hand-edited file must
 * never reach the output. An unrecognised value reads as null — no cause named —
 * rather than as a failure to parse the whole file, because the failure COUNT
 * next to it is still evidence and losing it would cost more than the cause.
 */
const FAILURES: ReadonlySet<string> = new Set<ControlPlaneFailure>([
  'unauthorized',
  'forbidden',
  'unreachable',
]);

/** The file's name, shared by the policy and the read-only status view. */
/**
 * The breaker's state file, in `dataDir`.
 *
 * EXPORTED because it is derived from an attachment and a detach has to remove
 * it. Left behind, a re-attach against a healthy plane opens on the previous
 * one's verdict: status prints a terminal-sounding refusal about a deployment
 * this machine no longer talks to, and — worse than cosmetic — `run` reads the
 * stale `openedAtMs` and skips the network entirely until the cooldown elapses.
 */
// Defined in @akasecurity/persistence, which sits below both detach surfaces
// (`aka detach` and the dashboard's settings action) and owns the list they
// both clear. Re-exported under this package's own name so its consumers are
// unaffected by where the string lives.
export const FORWARD_STATE_FILENAME = ATTACHED_FORWARD_STATE_FILENAME;
const STATE_FILENAME = FORWARD_STATE_FILENAME;

/**
 * Parse the state file's contents, or `null` when it says nothing usable.
 *
 * Shared by the policy's own reader and by `readForwardHealth` so the two can
 * never disagree about what a given file means — in particular about the future
 * `openedAtMs` clamp below, which they would otherwise each have to remember.
 * The two callers differ only in how they treat `null`: the policy resolves it
 * to CLOSED (forward normally), while the status view says nothing at all.
 */
function parseBreakerState(raw: string, nowMs: number): BreakerState | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as {
      consecutiveFailures?: unknown;
      openedAtMs?: unknown;
      lastFailure?: unknown;
    };
    const failures =
      typeof record.consecutiveFailures === 'number' && record.consecutiveFailures >= 0
        ? record.consecutiveFailures
        : 0;
    // A stamp we could not yet have written means the CLOCK moved, not that the
    // breaker is open — and reading it as open wedges forwarding off
    // PERMANENTLY. `run()`'s cooling path early-returns without rewriting the
    // file, so `at - openedAtMs` stays strongly negative and every later process
    // re-reads the same future stamp and returns null again, with nothing left
    // that can move it back. It does not take hostility to produce one: a laptop
    // that suspends, wakes and takes an NTP correction BACKWARDS leaves behind a
    // stamp ahead of the corrected clock. Same rule as a torn read — a value we
    // cannot have authored reads as CLOSED.
    const openedAtMs =
      typeof record.openedAtMs === 'number' &&
      Number.isFinite(record.openedAtMs) &&
      record.openedAtMs <= nowMs
        ? record.openedAtMs
        : null;
    // Absent for every file written before this field existed, which is the
    // common case on an already-deployed device: it reads as "no cause
    // recorded", the same as an unrecognised one, and the count and stamp
    // beside it stay usable.
    const lastFailure =
      typeof record.lastFailure === 'string' && FAILURES.has(record.lastFailure)
        ? (record.lastFailure as ControlPlaneFailure)
        : null;
    return { consecutiveFailures: failures, openedAtMs, lastFailure };
  } catch {
    // TORN READ. A half-written or garbage file must never resolve to "open":
    // an open breaker is a decision to STOP sending the organization its own
    // telemetry, and no corrupt byte on disk should make that decision on the
    // operator's behalf.
    return null;
  }
}

/** What the breaker knows, for a READ-ONLY consumer. */
export interface ForwardHealth {
  /** Failures since the last success. Monotonic across probes until one lands. */
  consecutiveFailures: number;
  /**
   * When the breaker last opened, or null when closed.
   *
   * ⚠ NOT "how long forwarding has been broken". `run()` re-stamps this on
   * every half-open probe, so the gap to now is bounded by one cooldown however
   * long the control plane has been down. `consecutiveFailures` is the duration-ish
   * signal; this one only says "the last attempt failed, recently".
   */
  openedAtMs: number | null;
  /**
   * How the last failure failed, or null when nothing has failed since the last
   * success — and also null for a file written before this field existed, or one
   * carrying a value this build does not recognise.
   *
   * The three are collapsed on purpose. Every one of them means the same thing
   * to a renderer: there is no cause here that can be named, so say what is
   * known and stop. Splitting them would create states a caller has to handle
   * and cannot act on differently.
   */
  lastFailure: ControlPlaneFailure | null;
}

/**
 * Read the breaker's bookkeeping WITHOUT touching it — for `/aka:status`.
 *
 * Synchronous and strictly read-only: the status renderer is sync and total,
 * and a status command must never open, close or re-stamp the breaker it is
 * describing. Returns `null` when the file is absent, unreadable or unusable,
 * which the caller renders as "nothing recorded" rather than as health — the
 * happy path writes no file at all, so an absent file genuinely means no
 * failure has been recorded, not that a forward has ever succeeded.
 */
export function readForwardHealth(dir: string, nowMs = Date.now()): ForwardHealth | null {
  try {
    return parseBreakerState(readFileSync(join(dir, STATE_FILENAME), 'utf8'), nowMs);
  } catch {
    return null;
  }
}

export interface ForwardPolicyDeps {
  /** Directory holding `attached-state.json`. */
  dir: string;
  now?: () => number;
}

/**
 * Why a forward produced no value.
 *
 * THREE of these are not verdicts of the control plane, and are kept apart
 * from the rest deliberately — none may be counted toward the breaker's
 * FAILURE count or written down as its `lastFailure`. That is the same
 * distinction `runPolicySync` draws by returning `null` for a sync it never
 * performed.
 *
 * Two of them are cases where NO ATTEMPT WAS MADE:
 *
 *   `breaker-open`    the breaker skipped the network entirely.
 *   `invalid-request` this machine refused to send a body that does not satisfy
 *                     the route's published contract. The sharper of the pair,
 *                     because it is DETERMINISTIC: counting it would let one
 *                     local shape bug open the breaker and suppress every
 *                     unrelated forward while status reported an outage that
 *                     never happened.
 *
 * `route-absent` is NOT that — the request was made and ANSWERED, a 404
 * because this deployment predates the batch route. That is not a statement
 * about this device's credential or the plane's health, so it is not a
 * verdict either — but unlike the two above it IS positive evidence of
 * REACHABILITY, which is the only thing the breaker measures. A half-open
 * probe that lands on it therefore restores `openedAtMs` to null (see
 * `run()`'s catch) rather than merely declining to advance it — the probe
 * re-stamps `openedAtMs` BEFORE the op runs, and leaving it re-stamped would
 * suppress the single-event retry `forwardBatch` uses this reason to trigger,
 * answering it with a freshly-cooled `breaker-open`. The restore touches
 * ONLY `openedAtMs`, never `consecutiveFailures` or `lastFailure` — this
 * breaker is shared by every route a gateway forwards through, so an answer
 * on ONE route is not permission to erase a failure count or a cause a
 * DIFFERENT route just earned.
 *
 * `rejected` is answered too — a 4xx other than 401/403/404, the deployment
 * refusing the BODY, the server-side twin of `invalid-request` — but it DOES
 * count toward the breaker, unlike every reason above. The difference from
 * `route-absent` is what a 404 versus a 4xx body refusal is EVIDENCE OF: a
 * 404 states which version the deployment runs, true of the whole deployment
 * regardless of which row asked. A body refusal is schema drift, and schema
 * drift is a property of the BUILD, not of one row — a deployment that
 * refuses one event's shape refuses all fifty sharing that shape. Exempting
 * it the way `route-absent` is exempt would isolate a single "bad" event
 * forever at no cost to the breaker: every chunk 4xx's, every single retry
 * 4xx's identically, and nothing ever opens the circuit — the exact storm the
 * 429 exclusion above exists to prevent, for every other status this range
 * still admits. So it is recorded through the SAME path an ordinary failure
 * takes, just with its own `reason` returned to the caller: three rejected
 * chunks open the breaker exactly as three timeouts would, while
 * `forwardBatch` still isolates the row that genuinely is alone.
 */
export type ForwardFailureReason =
  ControlPlaneFailure | 'breaker-open' | 'invalid-request' | 'route-absent' | 'rejected';

/**
 * What one forward did. A DISCRIMINATED UNION rather than `T | null`, because
 * `null` had to stand for four different things at once — refused, timed out,
 * unreachable, never attempted — and the caller that most needed to tell them
 * apart (`/aka:status`, via the file this policy writes) could not.
 *
 * `ok: false` is still not an error. G1 is unchanged and is the reason this is a
 * RESULT and not a throw: every caller has already completed its local write and
 * must return that result whatever the control plane did. The union widens what a
 * caller MAY observe; it obliges none of them to observe anything, and several
 * call sites in `attached-gateway.ts` still discard it outright.
 */
export type ForwardResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: ForwardFailureReason };

export interface ForwardPolicy {
  /**
   * Run one forward. Resolves with `{ ok: true, value }` on success and
   * `{ ok: false, reason }` on ANY failure — refusal, timeout, transport error,
   * or an open breaker. It never throws and never rejects, because every caller
   * has already completed its local write and must return that result
   * regardless (G1).
   */
  run<T>(op: () => Promise<T>, opts?: { decisionPath?: boolean }): Promise<ForwardResult<T>>;
}

/**
 * The forward budget + two-level circuit breaker guarding every write-through
 * to the control plane.
 *
 * Two levels because they solve different halves of the same problem. The
 * IN-PROCESS breaker stops a single long-lived process from re-paying the
 * timeout on every write once the control plane is unreachable. The CROSS-PROCESS
 * one matters more here and is the reason for the file at all: a Claude Code
 * hook is a SHORT-LIVED process, so in-process state dies with it and the very
 * next hook would re-pay the full budget from a clean slate. Persisting the
 * open breaker is what makes "the control plane is down" cost one timeout per
 * cooldown rather than one per hook.
 */
export function createForwardPolicy(deps: ForwardPolicyDeps): ForwardPolicy {
  const now = deps.now ?? (() => Date.now());
  const file = join(deps.dir, STATE_FILENAME);

  let state: BreakerState | null = null;
  let loading: Promise<BreakerState> | null = null;

  async function readState(): Promise<BreakerState> {
    let raw: string;
    try {
      raw = await readFile(file, 'utf8');
    } catch {
      // Absent, unreadable, permission-denied — all mean "nothing tells us the
      // breaker is open", which is CLOSED. Deliberately wider than
      // posture-store's read: there, an I/O error had to be distinguished from
      // a missing file because a device IDENTITY was at stake and guessing
      // destroyed continuity. Here the worst case of guessing wrong is one
      // extra bounded forward attempt, whereas failing CLOSED-shut on an
      // unreadable file would silently disable forwarding forever.
      return { ...CLOSED };
    }
    // Anything the shared parser cannot vouch for ⇒ CLOSED, i.e. forward
    // normally. See parseBreakerState for why that direction is the safe one.
    return parseBreakerState(raw, now()) ?? { ...CLOSED };
  }

  async function load(): Promise<BreakerState> {
    if (state !== null) return state;
    // Single-flight: concurrent forwards in one process must not each read the
    // file. `loading` is cleared only after `state` is set, so every waiter
    // observes the same resolved state.
    loading ??= readState().then((loaded) => {
      state = loaded;
      loading = null;
      return loaded;
    });
    return loading;
  }

  async function persist(next: BreakerState): Promise<void> {
    state = next;
    try {
      await ensureDataDir(deps.dir);
      // Per-write suffix, not a fixed `${file}.tmp`: concurrent hooks each
      // write their own temp file, so the second rename cannot hit ENOENT
      // because the first already moved a shared name away (the same reasoning
      // posture-store.ts documents for its throttle stamp).
      const tmp = `${file}.${randomUUID()}.tmp`;
      await writeFile(tmp, JSON.stringify(next), { encoding: 'utf8', mode: DATA_FILE_MODE });
      // Atomic swap so a concurrent reader never observes a torn file.
      await rename(tmp, file);
    } catch {
      // Persisting breaker state is an optimisation, never a correctness
      // requirement: losing it costs one extra bounded attempt next process.
      // It must never propagate into the caller's fail-open path.
    }
  }

  return {
    async run<T>(
      op: () => Promise<T>,
      opts?: { decisionPath?: boolean },
    ): Promise<ForwardResult<T>> {
      const budget = opts?.decisionPath === true ? DECISION_PATH_BUDGET_MS : FORWARD_BUDGET_MS;
      let current: BreakerState;
      try {
        current = await load();
      } catch {
        current = { ...CLOSED };
      }

      // Shared by the two catch arms that answer a half-open probe without
      // treating it as a verdict: `invalid-request` restores the EXACT
      // pre-probe `openedAtMs` (nothing reached the network, so nothing may
      // move); `route-absent` restores it to `null` (the deployment ANSWERED,
      // which is reachability evidence). Both preserve `consecutiveFailures`
      // and `lastFailure` unconditionally: this breaker is shared by every
      // route a gateway forwards through, so neither call may erase a count
      // or a cause a DIFFERENT route earned. `rejected` does NOT use this —
      // see its own arm below for why it needs the opposite treatment.
      const restoreOpenedAtMs = (openedAtMs: number | null): Promise<void> =>
        persist({
          consecutiveFailures: current.consecutiveFailures,
          openedAtMs,
          lastFailure: current.lastFailure,
        });

      // Shared by `rejected` and the generic failure path below: both are
      // real evidence the breaker must count, differing only in what they
      // record as `lastFailure`. Recording `'unreachable'` for `rejected`
      // rather than widening `ControlPlaneFailure` is deliberate — that type
      // is deliberately coarse for the reason its own docblock gives, and a
      // 4xx body refusal has no more of a human remediation than a timeout
      // does; it belongs in the same "no verdict we are willing to name"
      // bucket.
      const recordFailure = (cause: ControlPlaneFailure): Promise<void> => {
        const failures = current.consecutiveFailures + 1;
        const shouldOpen = current.openedAtMs !== null || failures >= BREAKER_FAILURE_THRESHOLD;
        return persist({
          consecutiveFailures: failures,
          openedAtMs: shouldOpen ? now() : null,
          lastFailure: cause,
        });
      };

      const at = now();
      if (current.openedAtMs !== null) {
        if (at - current.openedAtMs < BREAKER_COOLDOWN_MS) {
          // Open and still cooling: skip the network entirely. This is the
          // whole point of the breaker — no timeout is paid at all.
          //
          // Nothing is persisted here, and that is the same rule the failure
          // arm below follows in reverse: the file records what the BACKEND
          // did, and on this path the control plane was not asked. Re-stamping it
          // would also destroy the one number that measures the outage, since
          // every skipped hook would look like another attempt.
          return { ok: false, reason: 'breaker-open' };
        }
        // Cooldown elapsed ⇒ HALF-OPEN. Re-stamping `openedAtMs` to `at`
        // before the probe keeps the rest of THIS process behind the cooldown
        // again, so one long-lived process issues one probe. Across processes
        // it is a read-then-write with no lock, so two hooks that both read the
        // same expired stamp will both probe — harmless, since each probe is
        // bounded and the loser simply re-opens, but it is a narrowing rather
        // than the mutual exclusion a lock would give.
        // `lastFailure` rides through unchanged: a probe re-stamps the breaker,
        // it does not re-diagnose it, and the refusal that opened this breaker
        // is still why the device is silent until something SUCCEEDS.
        await persist({
          consecutiveFailures: current.consecutiveFailures,
          openedAtMs: at,
          lastFailure: current.lastFailure,
        });
      }

      try {
        // The op is CALLED INSIDE the try, not passed as an already-built
        // promise: a dep that throws synchronously would otherwise throw while
        // the argument is being constructed, before any handler is attached,
        // and reject out of a method whose entire contract is that it does not.
        const value = await withTimeout(op(), budget);
        if (current.openedAtMs !== null || current.consecutiveFailures > 0) {
          // CLOSED clears `lastFailure` along with the count, and it has to: a
          // forward has just landed, so the last thing the control plane said about
          // this device is yes. Leaving the old cause behind would have status
          // keep naming a 403 that a success has since disproved.
          await persist({ ...CLOSED });
        }
        return { ok: true, value };
      } catch (err) {
        // The one place the failure is still in hand. Classified HERE rather
        // than by the caller, because this is also the only place that can
        // write it down — most call sites drop the result, and the
        // reader that needs it (`/aka:status`) runs in a different process
        // minutes or days later.
        //
        // A refusal is terminal in a way a timeout is not, so tripping the
        // breaker on the FIRST 403 rather than the third is tempting.
        // Deliberately not done, and not merely out of caution: it would make
        // how quickly this device stops trying depend on a status that a
        // captive portal, an authenticating proxy, or a misconfigured gateway
        // can assert on the control plane's behalf. The threshold stays ONE number,
        // independent of anything the network claims; the classification is
        // used only to EXPLAIN the outage, never to change what the breaker
        // does. Explaining it was the part that was missing.
        // A body this machine refused to SEND is a defect here, not a verdict
        // there. Recording it would move the breaker on evidence the control
        // plane never supplied; see ForwardFailureReason.
        if (isInvalidRequest(err)) {
          // Nothing reached the network on this path — the body was refused
          // before a socket opened — so unlike the two arms below this is no
          // evidence of reachability, and unlike a real failure it is no
          // evidence of anything about the deployment at all. The only correct
          // outcome is for this call to have changed NOTHING, which is why the
          // restore target is `current.openedAtMs` — exactly what `load()`
          // returned before `run()` touched the file — rather than `null`.
          //
          // Left un-restored, the re-stamp is a real bug and not merely
          // untidy: `openedAtMs` moves forward to THIS probe's own timestamp,
          // so the breaker looks like it just opened again and the NEXT probe
          // is measured from a moment nothing was learned at — a caller
          // retrying a single malformed event during the half-open window pays
          // a second full cooldown for a chance the first one already earned.
          if (current.openedAtMs !== null) await restoreOpenedAtMs(current.openedAtMs);
          return { ok: false, reason: 'invalid-request' };
        }
        // `route-absent` is the deployment ANSWERING — a 404, because this
        // deployment predates the batch route — never a refusal of this
        // credential and never an outage. Counting it toward the breaker
        // would open it against a deployment responding to every request it
        // understands, and suppress every unrelated forward for the cooldown.
        // The caller's remedy is the older route, not to stop trying.
        if (isRouteAbsent(err)) {
          // Restores ONLY `openedAtMs`, to `null` rather than back to
          // `current.openedAtMs` as `invalid-request` above does — the
          // difference is that THIS call reached the deployment and got an
          // answer, which is reachability evidence the invalid-request arm
          // never has. `consecutiveFailures`/`lastFailure` ride through
          // untouched regardless: this breaker is shared by every route a
          // gateway forwards through, so an answer on ONE of them is not
          // permission to erase a count or a cause a DIFFERENT route earned.
          //
          // The re-stamp still has to be undone, and for the same reason as
          // above: a probe re-stamps `openedAtMs` before the op runs, and
          // leaving it re-stamped would answer the per-item retry this reason
          // exists to trigger with a freshly-cooled `breaker-open` — nothing
          // delivered and nothing counted.
          if (current.openedAtMs !== null) await restoreOpenedAtMs(null);
          return { ok: false, reason: 'route-absent' };
        }
        // `rejected` is ALSO the deployment answering — a 4xx body refusal —
        // but unlike `route-absent` it DOES count toward the breaker, exactly
        // like a genuine outage. The reason is what makes `route-absent` safe
        // to exempt: a 404 is a fact about which VERSION the deployment runs,
        // true of the whole deployment regardless of which row triggered it.
        // A 4xx body refusal is not that — "schema drift on the other side of
        // the wire" is a property of the BUILD, not of one row, so a
        // deployment that refuses one event's shape refuses all fifty. Left
        // exempt the way `route-absent` is, a sustained 422 would isolate a
        // single event costlessly forever — 51 requests a pass, breaker
        // permanently closed, nothing ever delivered, exactly the storm the
        // 429 exclusion above exists to prevent, for every status this range
        // still admits. Counting it is what bounds that: three rejected
        // chunks open the breaker exactly as three timeouts would, and the
        // isolation stays available for the row that genuinely is alone.
        if (isServerRejection(err)) {
          await recordFailure('unreachable');
          return { ok: false, reason: 'rejected' };
        }

        const reason = classifyFailure(err);
        await recordFailure(reason);
        // Dropped, never spooled (G8). The local write already succeeded, so
        // the caller has a correct result to return.
        return { ok: false, reason };
      }
    },
  };
}
