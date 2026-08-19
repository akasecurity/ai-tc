/**
 * The two per-call store costs that sit inside the hook's 10 s budget, asserted
 * to stay FLAT as the store grows.
 *
 * A hook opens the store and writes one capture on every tool call, and a hook
 * that overruns its harness timeout is killed — which the harness reads as "no
 * opinion", letting the tool call through UNSCANNED. So these are not comfort
 * budgets; they are the margin between an audited call and a silent gap.
 *
 * ## What is asserted is a RATIO, and why it is not a wall-clock gate
 *
 * This repository does not gate a PR on wall-clock, and this file does not
 * either. What it gates on is the ratio between the SAME cost measured against
 * two stores an order of magnitude apart in size, taken in one process moments
 * apart. A ratio cancels the machine: a runner half the speed halves both
 * measurements and moves the quotient not at all. That is what makes it safe to
 * gate on where an absolute millisecond bound is not.
 *
 * The absolute bound this file used to carry is the mistake worth naming, since
 * the reasoning that produced it is seductive. It asserted a p95 against a
 * budget ~165x the measured median and called that headroom too wide to flake.
 * It flaked anyway: the same commit measured 43 ms on one CI run and 277 ms on
 * another, against a 30 ms budget, on a tree with no defect in it. A shared CI
 * runner does not get 1/165th as fast — it gets preempted, and a preempted
 * sample is unbounded. No headroom multiple is large enough to fix that,
 * which is why the shape had to change rather than the number.
 *
 * ## The estimator is the MINIMUM, and that is load-bearing
 *
 * A ratio is only as stable as the statistic on each side of it, and a quantile
 * is the wrong one here. Measured over 7 repetitions spanning an idle machine
 * and one oversubscribed to 3x its core count — at the 5k -> 50k pair this file
 * carried then, and not retaken since, because what it establishes is which
 * ESTIMATOR survives load rather than what either one reads at a given size:
 *
 * | estimator | `recordCapture` ratio | `openLocalDatabase` ratio |
 * | --------- | --------------------: | ------------------------: |
 * | minimum   |     0.993–1.071 (1.08x) |       0.972–1.033 (1.06x) |
 * | median    |     0.904–1.092 (1.21x) |       0.851–1.125 (1.32x) |
 * | p95       |     0.517–2.374 (4.60x) |      0.754–12.793 (16.97x) |
 *
 * The p95 row is the reason the estimator is named in the assertion rather than
 * left to taste: a single preemption anywhere in either sample set moves a
 * quantile ratio by more than a real regression would, so a p95 ratio would have
 * reproduced the flake it was brought in to fix. The minimum is the right
 * statistic for an UPPER bound on cost — noise only ever adds time, so the
 * fastest of n samples is the closest estimate of the work itself, and the one a
 * loaded runner cannot inflate.
 *
 * ## What the ratio cannot see, and what the backstop is for
 *
 * A ratio tests FLATNESS. It is blind to a regression that adds a constant: a
 * cost going from 0.06 ms to 500 ms at every size keeps a ratio of 1.0 and
 * passes. So one absolute bound stays, at `GROSS_REGRESSION_MS` — four orders of
 * magnitude above the measured cost, sized against the hook's 10 s harness
 * timeout rather than tuned to a measurement. It is NOT the flatness guard and
 * cannot substitute for one; equally the ratio cannot substitute for it. They
 * fail on different defects, which is why both are here.
 *
 * ## Why 2k -> 20k
 *
 * The SEPARATION is what the guard is made of, not the absolute size: a cost
 * that went linear in the table reads ~10x at a 10x size step, against a 3.0
 * ceiling. Any pair an order of magnitude apart states that property, so the
 * pair is chosen at the cheapest scale that still measures real work.
 *
 * It used to be 5k -> 50k, and the mistake worth naming is NOT that it was
 * sized against a bad local rate. The local figure it was chosen against —
 * "about 3.5 s to seed both" — is accurate; this pair measures 3.88 s. What was
 * never accounted for is how much slower the CI leg is, and that factor is far
 * larger than "several times": 116,970 ms on a macOS run that passed and
 * 135,237 ms on one that did not, against the 120,000 ms ceiling below, is
 * **~30x** the 3.88 s measured here. State it as a FACTOR, because that is the
 * form the next sizer needs — a local seed time means nothing on its own.
 *
 * Seeding is not flat per event, but it has no step in it either. Measured as
 * the fastest of three seeds into a FRESH store, one warm-up discarded, row
 * counts read back, on arm64 macOS 26.5.2 / Node 24.18.0 with nothing else
 * running:
 *
 * |  events | seed time | ms/event |
 * | ------: | --------: | -------: |
 * |   2,000 |     87 ms |   0.0434 |
 * |   3,000 |    128 ms |   0.0427 |
 * |   5,000 |    224 ms |   0.0448 |
 * |  20,000 |  1,117 ms |   0.0558 |
 * |  50,000 |  3,659 ms |   0.0732 |
 *
 * So 5k + 50k is 3.88 s here and 2k + 20k is 1.20 s — a 3.2x improvement, which
 * is where the headroom came from, and ~36 s once the 30x CI factor is applied.
 *
 * An earlier revision of this comment claimed a page-cache cliff at ~2,400
 * events and a 0.091 ms/event rate at 3k. Neither reproduces: the rate is flat
 * straight through that boundary (0.0434 at 2k, 0.0434 at 2.4k, 0.0427 at 3k)
 * and creeps ~1.7x across the whole 2k->50k range. The old numbers ran ~5-6x
 * high and could not be reproduced warm or cold — a first, unwarmed seed costs
 * only ~8% more here — so they are retracted rather than re-explained. Take the
 * rate yourself before sizing anything against it.
 *
 * The 1M end is exercised by hand and reported in `bench/queries.bench.ts`.
 *
 * ## How big a linear cost has to be before this sees it
 *
 * "Reads ~10x" holds only once the size-dependent term DOMINATES the baseline,
 * and that is a real limit rather than a quibble. The ratio is
 * `(base + 10k) / (base + k)` for a per-row cost `k` at the small size, so
 * clearing a ceiling of 3 needs `k >= 2/7` of the baseline — about 15 us against
 * the ~53 us `recordCapture` costs here, i.e. a per-row slope of ~7.6 ns, or a
 * linear term of ~0.15 ms by 20k rows.
 *
 * **That floor moved by 2.5x when the pair came down**, in exactly the
 * proportion the small size did, and it is the price the section above bought
 * its headroom with. Do not read the cut as free.
 *
 * The baseline is what makes that proportion exact, so it is measured at BOTH
 * sizes rather than assumed: fastest-of-200 `recordCapture` is 53.4 us at 2k and
 * 53.0 us at 5k (three runs each, spreads 53.4-59.5 and 53.0-61.1 — overlapping,
 * i.e. flat). Because the baseline does not move with the corpus, the floor
 * moves only with the small size, and 2.5x is the whole of it. An earlier
 * revision put this baseline at ~79 us and the one before it at ~58 us; both
 * were single unreplicated readings, and a 58 -> 79 "move" read out of them
 * would make the floor look like it had shifted 3.4x. It had not — a smaller
 * corpus making `recordCapture` dearer is backwards, and that is the tell that
 * such a number is load, not signal.
 *
 * Both ends of the range are measured, on this machine and at THIS pair — the
 * numbers a smaller pair invalidates are the numbers most likely to be carried
 * forward stale, so they are retaken rather than scaled:
 *
 *  - `SELECT COUNT(*) FROM audit_events` inside `recordCapture` leaves this file
 *    GREEN. SQLite answers that count from a covering index, so it is genuinely
 *    linear and still far under the floor.
 *  - `SELECT COUNT(*) FROM audit_events WHERE LENGTH(id) = 999` — the same scan
 *    with the index defeated, ~40 ns/row — took the ratio to 4.739 (0.1844 ms at
 *    2k against 0.8739 ms at 20k) and FAILED it.
 *
 * So: this catches a linear cost that meaningfully changes what the operation
 * costs, and does not catch one lost in the noise floor. A regression that only
 * bites past 20k rows is not caught here either.
 *
 * A caveat for whoever plants the next one, because it cost a cycle to find:
 * a mutation inside `recordCapture` is charged to the SEED as well, once per
 * row, so its cost there is QUADRATIC. A scan expensive enough per row
 * (`content LIKE '%zzz%'`, over a 240-character column) never reaches the
 * assertion at all — it overruns `SEED_TIMEOUT_MS` and reports as a hook
 * timeout, which is a red for the wrong reason and proves nothing about
 * flatness. Pick a cost above the floor and well under it.
 *
 * `/security` gets no test here, and the omission is deliberate rather than an
 * oversight: it MISSES its 2,000 ms budget at 1M events (5,945 ms measured), so
 * there is no passing assertion to write.
 *
 * ## The corpora are built in a HOOK, under a SETUP-sized ceiling
 *
 * Seeding both stores costs 1.20 s on arm64 macOS against measured work of
 * roughly 30 ms — the setup is orders of magnitude more expensive than
 * everything asserted, so it lives in `beforeAll` where the test's own budget
 * covers the measurement and nothing else. Left in an `it()` body it would spend
 * most of the `testTimeout` before the first sample, and a SYNCHRONOUS body
 * cannot be interrupted: it runs to completion and is then reported as a
 * timeout, which reads as a budget failure and is not one.
 *
 * `SEED_TIMEOUT_MS` bounds that setup and asserts nothing. Raising it to answer
 * a red is the mistake this file exists to avoid — the corpus comes down
 * instead, which is what the section above records having done. Note which way
 * round that is: a hook overrunning here is never evidence that the ceiling is
 * too low, because nothing is measured against it.
 *
 * ## Each cost is asserted in its own `it()`
 *
 * Two `expect`s in one body means the first failure short-circuits the second,
 * and the second then reports nothing on the runs that matter most. That is not
 * hypothetical: while both budgets shared a body, `openLocalDatabase` was never
 * once evaluated on the Windows leg, because the capture assertion above it
 * failed first. A cost with no reported measurement is a cost with no guard.
 */
import type { IngestEvent } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { CORPUS_EPOCH_MS, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const SMALL_EVENTS = 2_000;
const LARGE_EVENTS = 20_000;

/**
 * How much the ratio may drift before the cost counts as growing with the table.
 *
 * Measured worst case across idle and 3x-oversubscribed runs is 1.071, so this
 * is ~2.8x of observed spread. A cost linear in the table reads ~10x at this
 * size step and a square-root one ~3.16x, so both are caught; anything gentler
 * than a square root is not, which is the price of a ceiling loose enough not to
 * flake.
 */
const FLATNESS_CEILING = 3;

/**
 * The absolute backstop, for a regression that is slow at EVERY size and so
 * invisible to the ratio.
 *
 * Sized against the hook's 10 s harness timeout — a hook does one open and one
 * capture, so a tenth of that budget for either is already a catastrophe —
 * rather than against the ~0.06 ms and ~0.5 ms these actually cost. It is four
 * orders of magnitude of headroom on purpose: a bound that a preempted sample
 * can reach is the shape this file removed, and the minimum-of-n estimator is
 * what keeps even this one out of reach of a loaded runner.
 */
const GROSS_REGRESSION_MS = 1_000;

/**
 * The ceiling on CORPUS SETUP, distinct from the properties under test.
 *
 * A corpus is not a measurement, so this is sized for the slowest runner rather
 * than tuned: 1.20 s of work on this machine, against a CI leg measured at ~30x
 * that. Nothing is asserted against it — a hook that overran would report a
 * setup failure, which is what it would be.
 *
 * The number to watch is the RATIO of the two, not this constant. At the pair
 * this file used to seed it was 3%, measured — 117 s of a 120 s ceiling on the
 * macOS leg — which is not headroom, it is a coin toss, and it landed both ways
 * inside a single afternoon. Keep the seed far enough under this that a slow
 * runner cannot reach it, and cut the corpus when it stops being.
 */
const SEED_TIMEOUT_MS = 120_000;

const CAPTURE_SAMPLES = 200;
const OPEN_SAMPLES = 20;

/**
 * The fastest of `samples` — see the estimator note in the file header.
 *
 * Returns `+Infinity` for an empty set rather than 0, so a measurement loop that
 * never ran fails every bound below instead of satisfying all of them.
 */
function fastest(samples: number[]): number {
  return samples.length === 0 ? Number.POSITIVE_INFINITY : Math.min(...samples);
}

function makeEvent(scope: number, seq: number): IngestEvent {
  return {
    id: `ffffffff-0000-4000-8000-${String(scope * 1_000_000 + seq).padStart(12, '0')}`,
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date(CORPUS_EPOCH_MS + (scope + seq) * 1_000).toISOString(),
    // Distinct per call: the capture row is content-addressed, so a shared hash
    // would turn every sample after the first into an upsert onto one row — a
    // cheaper path than the insert under test, and one that would keep this
    // green after the insert had regressed.
    contentHash: `budget-probe-${String(scope)}-${String(seq)}`,
    content: 'refactor the session handler so a retry never reopens the store',
    metadata: { sessionId: '22222222-2222-4222-8222-222222222222' },
  };
}

interface Measured {
  readonly events: number;
  readonly captures: number[];
  readonly opens: number[];
}

/**
 * Seed a store of `events` and time both costs against it.
 *
 * Seeded and measured together, one store at a time, so each size is timed in
 * the same state: freshly written, its own pages hot. Measuring both sizes after
 * seeding both would leave the smaller store's pages evicted by the larger
 * seed — an asymmetry that lands entirely in the ratio.
 */
function seedAndMeasure(store: OwnedTempStore, events: number): Measured {
  const db = store.open();
  // Throws unless the rows are on disk. Every bound below is an upper bound on
  // time, and the fastest possible store is an empty one — so without this the
  // whole file would pass most convincingly at the moment the corpus stopped
  // being written.
  const corpus = seedCaptureCorpus(db, { events, sessions: 200, seed: 1 });

  const captures: number[] = [];
  for (let i = 0; i < CAPTURE_SAMPLES; i += 1) {
    const started = performance.now();
    db.recordCapture(makeEvent(events, i), []);
    captures.push(performance.now() - started);
  }

  const opens: number[] = [];
  for (let i = 0; i < OPEN_SAMPLES; i += 1) {
    const started = performance.now();
    const handle = openLocalDatabase(store.dataDir);
    opens.push(performance.now() - started);
    handle.close();
  }

  return { events: corpus.events, captures, opens };
}

describe(`store costs from ${SMALL_EVENTS.toLocaleString('en-US')} to ${LARGE_EVENTS.toLocaleString('en-US')} events`, () => {
  const stores: OwnedTempStore[] = [];
  let small: Measured;
  let large: Measured;

  beforeAll(() => {
    const smallStore = createTempStore('aka-scale-budget-small-');
    stores.push(smallStore);
    small = seedAndMeasure(smallStore, SMALL_EVENTS);

    const largeStore = createTempStore('aka-scale-budget-large-');
    stores.push(largeStore);
    large = seedAndMeasure(largeStore, LARGE_EVENTS);
  }, SEED_TIMEOUT_MS);

  afterAll(() => {
    for (const store of stores) store.destroy();
  });

  it('both corpora really are at the stated scale', () => {
    // Read back rather than trusted: the seed runs in a hook, so a body that
    // asserted nothing about it would compare whatever two stores it got.
    expect(small.events).toBe(SMALL_EVENTS);
    expect(large.events).toBe(LARGE_EVENTS);
  });

  it('the samples describe real work', () => {
    // A `performance.now()` that stopped advancing, or a loop that never ran,
    // reports 0 — which divides into a NaN ratio and satisfies no bound, but
    // says nothing about which side was empty. This names it.
    for (const [label, measured] of [
      ['small', small],
      ['large', large],
    ] as const) {
      expect(measured.captures).toHaveLength(CAPTURE_SAMPLES);
      expect(measured.opens).toHaveLength(OPEN_SAMPLES);
      expect(fastest(measured.captures), `${label} capture floor`).toBeGreaterThan(0);
      expect(fastest(measured.opens), `${label} open floor`).toBeGreaterThan(0);
    }
  });

  it('recordCapture stays flat as the store grows', () => {
    const smallest = fastest(small.captures);
    const largest = fastest(large.captures);
    const ratio = largest / smallest;

    expect(
      ratio,
      `recordCapture fastest-of-${String(CAPTURE_SAMPLES)} was ${smallest.toFixed(4)} ms at ` +
        `${SMALL_EVENTS.toLocaleString('en-US')} events and ${largest.toFixed(4)} ms at ` +
        `${LARGE_EVENTS.toLocaleString('en-US')} — a ratio of ${ratio.toFixed(3)} across a 10x ` +
        `size step, where a cost linear in the table would read ~10`,
    ).toBeLessThan(FLATNESS_CEILING);

    expect(largest, `recordCapture at ${LARGE_EVENTS.toLocaleString('en-US')} events`).toBeLessThan(
      GROSS_REGRESSION_MS,
    );
  });

  it('openLocalDatabase stays flat as the store grows', () => {
    const smallest = fastest(small.opens);
    const largest = fastest(large.opens);
    const ratio = largest / smallest;

    expect(
      ratio,
      `openLocalDatabase fastest-of-${String(OPEN_SAMPLES)} was ${smallest.toFixed(4)} ms at ` +
        `${SMALL_EVENTS.toLocaleString('en-US')} events and ${largest.toFixed(4)} ms at ` +
        `${LARGE_EVENTS.toLocaleString('en-US')} — a ratio of ${ratio.toFixed(3)} across a 10x ` +
        `size step, where a cost linear in the table would read ~10`,
    ).toBeLessThan(FLATNESS_CEILING);

    expect(
      largest,
      `openLocalDatabase at ${LARGE_EVENTS.toLocaleString('en-US')} events`,
    ).toBeLessThan(GROSS_REGRESSION_MS);
  });
});
