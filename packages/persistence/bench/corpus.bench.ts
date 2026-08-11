/**
 * Seeding a store from the deterministic fixture generator.
 *
 * This is the harness's own cost, and it is charged to every scale benchmark
 * this package will grow — `recordCapture` at 1M rows, the dashboard
 * aggregations at 1M events, the vault inventory at 100k entries all build
 * their input this way. If it regresses, each of those gets slower for a reason
 * that has nothing to do with the code it is measuring, and a trend chart shows
 * a product regression that is not there.
 *
 * It is also a real product measurement, because the corpus is written through
 * `recordCapture` rather than through INSERTs of its own. What moves this number
 * is the store's write path: the capture row, the definition upserts, and the
 * two dedup queries per finding, all of which grow with the table.
 *
 * WHAT EACH SAMPLE CONTAINS. One `mkdtemp`, one `openLocalDatabase` (migrations,
 * the `ensure*` passes and every repository construction), the generation
 * itself, and the teardown. The whole store is built and destroyed inside the
 * timed region ON PURPOSE: vitest's bench options are tinybench's per-CYCLE
 * hooks rather than per-iteration ones, so a store hoisted into a `setup` hook
 * would be shared across every iteration of a task and the corpus would
 * accumulate — each sample writing into a larger table than the last, and the
 * mean describing no particular store size at all. A self-contained iteration
 * pays a fixed cost and measures something stable, which is the better trade.
 *
 * That fixed cost was measured rather than assumed: the same lifecycle with
 * ZERO events is 12 ms, against 51 ms for the 1,000-event size and 519 ms for
 * the 10,000. So it is roughly a quarter of the small sample and around 2% of
 * the large one — which is why both sizes are kept. Read a movement in the small
 * one as possibly being about store OPENING, and a movement in the large one as
 * being about the write path.
 *
 * WHAT IS DELIBERATELY NOT HERE. `recordCapture` in isolation at a stated store
 * size, and the dashboard read queries at scale, are their own benchmarks
 * against their own budgets.
 *
 * NO ASSERTIONS, and there should be none: nothing in this repository gates a
 * PR on wall-clock, and a benchmark that threw would be a timing gate wearing a
 * different name. The budgets live in the timing GUARDS (`redos.test.ts`, the
 * isolation ceilings). This reports a trend.
 */
import { bench, describe } from 'vitest';

import { seedCaptureCorpus } from '../test/helpers/corpus.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/** Build a store, seed it, tear it down. Every iteration is identical. */
function seedFromScratch(events: number, sessions: number): void {
  const owned = createTempStore('aka-bench-corpus-');
  try {
    // Throws if the rows are not on disk afterwards, so a store that silently
    // refused every write cannot be timed as a fast one.
    seedCaptureCorpus(owned.open(), { events, sessions, seed: 1 });
  } finally {
    owned.destroy();
  }
}

describe('seed a store from the fixture generator', () => {
  // A sample here is 50-520 ms, against tinybench's 500 ms default sampling
  // window — so the defaults would take one or two samples of the large size and
  // report a relative margin of error wide enough to swallow any trend. These
  // ask for enough samples to mean something without making the nightly job
  // long: measured at ~7.1 s for the file, with a relative margin of error of
  // 1-5% on an idle machine across eight runs.
  //
  // On a BUSY one it is far wider — ±18% on the large size, measured with a
  // full test suite running alongside. That is the variance this job is
  // advisory-only for, and the reason to read a trend across nights rather than
  // to compare two adjacent runs.
  const options = { time: 0, iterations: 8, warmupIterations: 2, warmupTime: 0 };

  bench(
    '1,000 events across 25 sessions',
    () => {
      seedFromScratch(1_000, 25);
    },
    options,
  );

  bench(
    '10,000 events across 50 sessions',
    () => {
      seedFromScratch(10_000, 50);
    },
    options,
  );
});
