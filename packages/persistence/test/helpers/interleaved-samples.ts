/**
 * Timings of the same work against two stores, sampled INTERLEAVED — the one
 * place the two-size ratio suites under `test/performance/` take their samples.
 *
 * A ratio of two fastest-of-n readings cancels the machine only if both were
 * drawn from the same stretch of wall time. The minimum survives a slowdown that
 * reaches SOME of a side's samples; it cannot survive one lasting through every
 * sample on one side and none on the other, which is what timing each store
 * straight after its own seed allowed. `scale-budgets.test.ts` records the red
 * that cost.
 *
 * Four properties live here rather than in each suite, and
 * `interleaved-samples.test.ts` pins each of them without a clock:
 *
 *  - **Equal counts.** Every iteration makes one call per store and records
 *    both, so each side holds exactly `samples` readings per probe. The count is
 *    fixed by the loop bound, not by which branch ran.
 *  - **Alternating order.** The store that goes first alternates every
 *    iteration, and each probe's block starts on the store the previous block did
 *    not, so block entry — the first touch of a different statement and index —
 *    is not always paid by the same side.
 *  - **One probe at a time.** Each probe takes its samples in a block of its own
 *    rather than every probe being cycled on each iteration. Cycling the
 *    `/activity` reads through each connection per iteration read `listFirstPage`
 *    at 1.17-1.27 against 0.95-1.01 block by block (three runs of nine rounds on
 *    one pair of stores, arm64 macOS, Node 24), an asymmetry of its own.
 *  - **A drained queue between blocks.** A probe returning a promise nobody
 *    awaits leaves its continuation, and whatever value that holds, queued until
 *    the current task ends. Yielding to the event loop after each block releases
 *    them outside every timed call, so no more than one block's results are live
 *    while the next block is timed.
 */

export type Side = 'small' | 'large';

/** One timed call: which store, which probe, and its 0-based index within the probe's block. */
export interface InterleavedCall<Name extends string> {
  readonly side: Side;
  readonly name: Name;
  readonly iteration: number;
}

/** Readings per probe name, one record per store. */
export interface PairedSamples {
  readonly small: Record<string, number[]>;
  readonly large: Record<string, number[]>;
}

const SMALL_FIRST: readonly Side[] = ['small', 'large'];
const LARGE_FIRST: readonly Side[] = ['large', 'small'];

/**
 * Elapsed milliseconds of ONE call, measured around the call alone.
 *
 * The repository reads these suites time run their SQL synchronously and return
 * an already-resolved promise, so the elapsed time around the bare call is the
 * whole of the work and the promise is never awaited.
 *
 * A returned promise's rejection is CAUGHT rather than discarded, and the reason
 * is diagnostic rather than cosmetic: a bare promise that rejects is an unhandled
 * rejection — one per sample — and vitest may attribute that to an unrelated
 * test, so a broken read would fail somewhere else in the suite instead of as the
 * clean assertion its own file exists to give.
 *
 * The `catch` is deliberately EMPTY, and that is not a swallowed error. What
 * surfaces a broken read is the awaited call each suite makes once per read
 * before any sampling, which rejects the `beforeAll` with the read's own error.
 * Collecting the rejection here and rethrowing it after the sampling loop looks
 * stronger and cannot work: a `.catch` callback runs in a MICROTASK, so it has not
 * fired by the time a synchronous loop finishes, and the check would read
 * `undefined` every time. That exact dead code was written in
 * `security-page-scale.test.ts` first, and what caught it was fault-injecting a
 * read that rejects only after its first call — the suite stayed green through
 * all of its cases.
 */
export function timeCall(fn: () => unknown): number {
  const started = performance.now();
  const result = fn();
  const elapsed = performance.now() - started;
  if (result instanceof Promise) {
    void result.catch(() => {
      // See above: the suite's own awaited call reports a broken read. This
      // exists only so a rejection is never unhandled.
    });
  }
  return elapsed;
}

/**
 * `samples` readings of each of `names` against both stores, interleaved as the
 * file header describes.
 *
 * `time` makes ONE call and returns its elapsed milliseconds, usually through
 * `timeCall`. The timed window is the callback's own, so work that has to follow
 * the call — closing a handle it opened — can stay outside it.
 */
export async function sampleInterleaved<Name extends string>(
  names: readonly Name[],
  samples: number,
  time: (call: InterleavedCall<Name>) => number,
): Promise<PairedSamples> {
  const small: Record<string, number[]> = {};
  const large: Record<string, number[]> = {};
  for (const [block, name] of names.entries()) {
    const onSmall: number[] = [];
    const onLarge: number[] = [];
    for (let iteration = 0; iteration < samples; iteration += 1) {
      // NaN until timed, so a side that was somehow skipped poisons its minimum
      // and fails every bound rather than satisfying one.
      const elapsed: Record<Side, number> = { small: Number.NaN, large: Number.NaN };
      for (const side of (block + iteration) % 2 === 0 ? SMALL_FIRST : LARGE_FIRST) {
        elapsed[side] = time({ side, name, iteration });
      }
      onSmall.push(elapsed.small);
      onLarge.push(elapsed.large);
    }
    small[name] = onSmall;
    large[name] = onLarge;
    await yieldToEventLoop();
  }
  return { small, large };
}

/** Resolves on the next turn of the event loop, after the microtask queue has drained. */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}
