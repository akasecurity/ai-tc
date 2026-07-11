// Throttled, detached spawn of the token-usage reconcile worker.
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

import { throttled } from '@akasecurity/plugin-sdk';

import { safeSessionId } from './tail.ts';

// Min gap between reconcile spawns. Stop fires once per turn; batching a few turns
// into one tail pass is lossless (the offset read is cumulative), so
// this window is purely a freshness-vs-cost knob, not a correctness one.
const RECONCILE_THROTTLE_MS = 30_000;

// Marker-file PREFIX for the reconcile throttle. The marker is
// namespaced PER SESSION (`${prefix}-${sessionId}`): each spawned worker reconciles
// ONLY the one session it is handed via argv, so a single global marker would let
// the first session in a 30s window starve every OTHER concurrent session (multiple
// tabs/projects — common) of its live capture until it won a later window, quietly
// regressing the "live per-turn capture" goal. Per-session markers throttle each
// session independently while still batching that session's own turns.
const RECONCILE_MARKER_PREFIX = 'reconcile-last-attempt';

/**
 * Trigger a background reconcile of one session's transcript tail. Throttle-checks
 * first; if not throttled, spawns `reconcile.js` DETACHED + unref, forwarding the
 * session id and transcript path as argv. Returns immediately — the hook adds no
 * latency. `reconcile.js` is resolved next to this module so the bundled hook
 * script finds its compiled sibling in `scripts/`.
 */
export function triggerReconcile(dataDir: string, sessionId: string, transcriptPath: string): void {
  try {
    // The session id rides in from hook stdin — sanitize before it becomes a
    // marker filename so it can never name anything outside dataDir.
    const marker = `${RECONCILE_MARKER_PREFIX}-${safeSessionId(sessionId)}`;
    if (throttled(dataDir, marker, RECONCILE_THROTTLE_MS)) return;
    const here = dirname(fileURLToPath(import.meta.url));
    const child = spawn(process.execPath, [join(here, 'reconcile.js'), sessionId, transcriptPath], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
  } catch {
    // Fail-open: the next Stop or the SessionStart catch-up recovers the tail.
  }
}
