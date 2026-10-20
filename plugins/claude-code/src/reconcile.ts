/**
 * Detached token-usage reconcile worker.
 * Spawned DETACHED by the Stop hook (and the SessionStart catch-up) so the live
 * per-turn capture never adds hook latency — this process outlives the hook and
 * does the actual read/parse/write off the hot path:
 *
 *   node scripts/reconcile.js <sessionId> <transcriptPath> [<dueAt> [trailing]]
 *
 * It reconciles ONLY the new transcript tail (from the stored per-session byte
 * offset) into idempotent `llm_call` leaves under the session root, in one
 * transaction. Both args come straight from the Stop payload — no path
 * reconstruction. A held pass spawns it again with a third arg, the time its
 * follow-up pass is due, and the worker waits for that time. A call the throttle
 * held back spawns it with the time that throttle window closes as the third arg
 * and `trailing` as the fourth; the worker waits for that time and then runs an
 * ordinary pass (see history/reconcile-worker.ts). Fully fail-open: any error (a locked store, a
 * missing file, a malformed arg) drops this pass silently; the next Stop or
 * SessionStart catch-up recovers the tail idempotently. Always exits 0.
 */
import { runReconcileWorker } from './history/reconcile-worker.ts';

try {
  await runReconcileWorker(process.argv.slice(2));
} catch {
  // Fail-open: the next pass recovers this tail idempotently.
}
process.exit(0);
