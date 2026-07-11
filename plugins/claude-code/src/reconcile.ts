/**
 * Detached token-usage reconcile worker.
 * Spawned DETACHED by the Stop hook (and the SessionStart catch-up) so the live
 * per-turn capture never adds hook latency — this process outlives the hook and
 * does the actual read/parse/write off the hot path:
 *
 *   node scripts/reconcile.js <sessionId> <transcriptPath>
 *
 * It reconciles ONLY the new transcript tail (from the stored per-session byte
 * offset) into idempotent `llm_call` leaves under the session root, in one
 * transaction. Both args come straight from the Stop payload — no path
 * reconstruction. Fully fail-open: any error (a locked store, a missing file, a
 * malformed arg) drops this pass silently; the next Stop or SessionStart catch-up
 * recovers the tail idempotently. Always exits 0.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { reconcileSessionTail } from './history/usage.ts';

try {
  const sessionId = process.argv[2];
  const transcriptPath = process.argv[3];
  // Both args are required — without them there is nothing to reconcile. A missing
  // arg means the spawn was malformed; drop the pass rather than guess a path.
  if (sessionId && transcriptPath) {
    const config = loadConfig();
    await reconcileSessionTail(config, sessionId, transcriptPath);
  }
} catch {
  // Fail-open: the next pass recovers this tail idempotently.
}
process.exit(0);
