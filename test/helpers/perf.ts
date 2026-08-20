/**
 * The shared pieces of a `test/performance/` suite that measures a walk.
 *
 * Three suites drive the adversarial corpus against the three tree walkers, and
 * these two values were byte-identical in all three. That matters more than the
 * line count: `fastestOf` is not a convenience, it is the ESTIMATOR the whole
 * tier rests on, so a correction to it — discarding two warm-ups instead of one,
 * say — applied to one copy and missed in the other two leaves those two
 * asserting against the weaker form while reading identically.
 *
 * It lives beside the corpus those suites already import rather than inside any
 * one package, for the reason the corpus itself does: a package wall blocks the
 * import, and private copies drift.
 */

/**
 * Ceiling for a case whose fixture is thousands of files.
 *
 * THE PER-TEST TIMEOUT IS NOT THE GATE. A row's wall clock is dominated by
 * BUILDING its tree — thousands of individual `writeFileSync` calls, which cost
 * an order of magnitude more on the Windows runner than on a developer machine;
 * one case measured 69,234 ms there for 5,000 files against ~400 ms locally.
 * Leaving that under vitest's default makes the fixture the binding constraint,
 * so a row goes red for being slow to SET UP and the failure reads as a slow
 * walk. This is big enough that the build never decides the outcome, and small
 * enough that a walk which stopped terminating still fails rather than hanging
 * the suite; the row's own budget is what fails a walk that got slower.
 */
export const FIXTURE_TIMEOUT_MS = 120_000;

/**
 * The fastest of `runs` passes, after one discarded warm-up.
 *
 * The minimum rather than a mean or a p95: noise only ever ADDS time, so the
 * fastest sample is the closest a loaded machine gets to the code's own cost,
 * and it is the one estimator a contended shared runner cannot inflate.
 */
export function fastestOf(runs: number, body: () => void): number {
  body();
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const started = performance.now();
    body();
    best = Math.min(best, performance.now() - started);
  }
  return best;
}
