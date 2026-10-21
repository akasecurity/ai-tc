// Detached spawns of the token-usage reconcile worker: the throttled one a hook
// makes, the trailing one that closes a throttle window, and the follow-up a held
// pass asks for.
//
// Detached + unref + on-disk min-gap marker so the hook never waits on it. It
// passes the session id + transcript path through to the worker via argv, so the
// Stop hook never reconstructs a path — it forwards exactly what the Stop payload
// handed it.
//
// Fully fail-open: the hook NEVER waits on or is broken by the reconcile. The child
// outlives this process (detached + unref); a spawn failure is swallowed and the
// next Stop (or the SessionStart catch-up) recovers the tail idempotently.
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gatePerKey } from '@akasecurity/plugin-sdk';
import type { PendingHold } from '@akasecurity/plugin-sdk/account';

import type { HeldPass } from './tail.ts';
import { safeSessionId } from './tail.ts';

// Min gap between reconcile spawns. Stop fires once per turn; batching a few turns
// into one tail pass is lossless (the offset read is cumulative) as long as a pass
// still follows the last of them, which is what the trailing pass below is for.
const RECONCILE_THROTTLE_MS = 30_000;

// The fourth argument of a worker spawned for the trailing pass of a throttle
// window: its third is when that window closes, and the worker runs a plain pass
// then, which is the follow-up of no hold.
export const TRAILING_MODE = 'trailing';

// Marker-file PREFIX for the reconcile throttle. The marker is
// namespaced PER SESSION (`${prefix}-${sessionId}`): each spawned worker reconciles
// ONLY the one session it is handed via argv, so a single global marker would let
// the first session in a 30s window starve every OTHER concurrent session (multiple
// tabs/projects — common) of its live capture until it won a later window, quietly
// regressing the "live per-turn capture" goal. Per-session markers throttle each
// session independently while still batching that session's own turns. Markers
// for sessions idle past a day are removed as new attempts are recorded (see
// `throttledPerKey`), so one file per session does not accumulate for ever.
const RECONCILE_MARKER_PREFIX = 'reconcile-last-attempt';

/**
 * Trigger a background reconcile of one session's transcript tail. Gates the call
 * on the session's throttle window: the first call of a window spawns
 * `reconcile.js` DETACHED + unref, forwarding the session id and transcript path as
 * argv, and a call the window holds back spawns one worker that waits until the
 * window closes and then runs, so the last call of a window is never dropped.
 * Later calls in that window spawn nothing. Returns immediately — the hook adds no
 * latency. `reconcile.js` is resolved next to this module so the bundled hook
 * script finds its compiled sibling in `scripts/`.
 */
export function triggerReconcile(dataDir: string, sessionId: string, transcriptPath: string): void {
  try {
    // The session id rides in from hook stdin — sanitize before it becomes a
    // marker filename so it can never name anything outside dataDir.
    const key = safeSessionId(sessionId);
    const gate = gatePerKey(dataDir, RECONCILE_MARKER_PREFIX, key, RECONCILE_THROTTLE_MS);
    if (gate.kind === 'run') spawnWorker([sessionId, transcriptPath]);
    else if (gate.kind === 'trail') {
      spawnWorker([sessionId, transcriptPath, String(gate.dueAt), TRAILING_MODE]);
    }
  } catch {
    // Fail-open: the next Stop or the SessionStart catch-up recovers the tail.
  }
}

/**
 * Spawn a worker that waits until `dueAt` (epoch milliseconds) and then runs the
 * follow-up pass of a held tail. It is not behind the reconcile throttle: that
 * window batches a session's turns, and a follow-up is one pass the hold asked
 * for. Fully fail-open: a spawn that fails leaves the hold to the next pass.
 */
export function scheduleFollowUp(sessionId: string, transcriptPath: string, dueAt: number): void {
  try {
    spawnWorker([sessionId, transcriptPath, String(dueAt)]);
  } catch {
    // Fail-open: a later pass finds the follow-up due and asks for another.
  }
}

function spawnWorker(args: readonly string[]): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const child = spawn(process.execPath, [join(here, 'reconcile.js'), ...args], {
    detached: true,
    stdio: 'ignore',
  });
  // A spawn that cannot start reports an 'error' event; unhandled, it ends the process.
  child.on('error', () => undefined);
  child.unref();
}

// How long after the first, second and third held pass of a tail its follow-up
// is due. The pass after the third finds the hold budget spent and writes, 8.5
// minutes after the first hold, inside the fifteen the budget allows.
export const FOLLOW_UP_DELAYS_MS = [30_000, 120_000, 360_000] as const;

/**
 * The checkpoint's hold once a pass has held, and the due time of the follow-up
 * to spawn, if any. A follow-up already asked for and not yet due is kept and
 * none is asked for: one at most is outstanding. One that is due is spent or lost,
 * and so is the one this pass is (`ownDue`), so the hold asks for the next.
 */
export function planFollowUp(input: {
  readonly held: PendingHold;
  readonly before: HeldPass | undefined;
  readonly ownDue: number | undefined;
  readonly now: number;
}): { readonly pending: HeldPass; readonly dueAt: number | undefined } {
  const queued = input.before?.followUpAt;
  if (queued !== undefined && queued !== input.ownDue && queued > input.now) {
    return { pending: { ...input.held, followUpAt: queued }, dueAt: undefined };
  }
  const delay = FOLLOW_UP_DELAYS_MS[input.held.passes - 1];
  if (delay === undefined) return { pending: input.held, dueAt: undefined };
  const dueAt = input.now + delay;
  return { pending: { ...input.held, followUpAt: dueAt }, dueAt };
}
