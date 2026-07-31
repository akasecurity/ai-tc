/**
 * A scan worker that announces a second rule only near the end of the job, then
 * hangs — the shape of a machine that froze mid-scan rather than a rule that
 * cannot return.
 *
 * The parent blames whichever rule was last announced, so without a share test
 * this worker gets rule 1 quarantined forever on the strength of having been
 * resident when the deadline happened to land. A fixed millisecond floor cannot
 * separate the two cases: any freeze long enough to matter clears it. The share
 * test can, because a rule that truly cannot return is entered early and holds
 * the thread for most of the job.
 *
 * Timings are wall-clock and deliberately one-sided: `ANNOUNCE_AT_MS` is chosen
 * so rule 1's residency clears the shipped 500ms floor comfortably while
 * staying well under half the job. A slow runner only shrinks that share
 * further, so the assertion cannot flip.
 *
 * Node loads this file directly, so it stays on plain type annotations like the
 * worker it replaces.
 */
import { parentPort } from 'node:worker_threads';

// Long enough that rule 1's residency beats ATTRIBUTION_MIN_RULE_MS on any
// runner; short enough that it is a minority of the test's 3s budget.
const ANNOUNCE_AT_MS = 1_800;

// Block this thread without burning a core. The worker has nothing else to do,
// and a busy-wait would compete with the parent for CPU on a loaded runner.
function block(ms: number): void {
  const idle = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(idle, 0, 0, ms);
}

parentPort?.on('message', () => {
  parentPort?.postMessage({ kind: 'progress', index: 0 });
  block(ANNOUNCE_AT_MS);
  // Announced with only a sliver of the budget left, then never returns.
  parentPort?.postMessage({ kind: 'progress', index: 1 });
  for (;;) block(60_000);
});

parentPort?.postMessage({ kind: 'ready' });
