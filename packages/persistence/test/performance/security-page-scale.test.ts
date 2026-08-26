/**
 * The three `/security` reads whose cost must NOT grow with the store, asserted
 * as a ratio across two store sizes.
 *
 * ## Why this file exists next to the plan guard
 *
 * `hot-read-query-plans.test.ts` asserts what SQLite DOES — which index, which
 * scan — and that is the right shape for "no hot read passes over an unindexed
 * table". It cannot express the property here, in either direction. A plan that
 * reads as ideal can still be linear in the store: `mttrTrend` used to drive
 * from `audit_events` on an index, joining every capture event before its window
 * predicate could reject a row, and every step of that plan was a SEARCH. And a
 * plan that reads as a full scan can be bounded: `recentFindings` deliberately
 * scans `idx_audit_started_at` so its LIMIT can stop early, and EXPLAIN QUERY
 * PLAN has no text for "terminates after 500 rows".
 *
 * So the plans pin the mechanism and this pins the consequence. Neither implies
 * the other.
 *
 * ## The experiment: hold the ANSWER fixed, grow the store
 *
 * All three reads return a bounded answer — the newest 500 findings, the newest
 * 20 resolutions, a 30-day MTTR trend over a fixed resolution set. So the
 * property is stated as: with the same number of rows to RETURN, a ten-fold
 * larger store must not cost meaningfully more.
 *
 * That is sharper than growing everything at once. If the corpus's resolutions
 * scaled with its events, the old quadratic form of `recentlyResolved`
 * (O(code_change events x resolved keys)) would read ~100x at a 10x step while a
 * correct linear-in-resolutions form read ~10x — a real separation, but one where
 * both arms move and the ceiling has to sit somewhere in between. Holding the
 * resolution count fixed instead makes the correct answer FLAT and the defective
 * one linear, so the ceiling separates 1 from 10 rather than 10 from 100.
 *
 * `RESOLUTION_TARGET` is what that costs: `resolutionRate` is a fraction of
 * trackable findings, and trackable findings scale with events, so the rate is
 * scaled by 1/events to keep the product roughly constant. "Roughly" is not good
 * enough to leave unchecked — a calibration that drifted would silently turn this
 * back into the both-arms-move experiment — so the two corpora's actual
 * resolution counts are asserted to be within `RESOLUTION_TOLERANCE` of each
 * other before any ratio is read.
 *
 * ## The estimator is the MINIMUM, and the bound is a RATIO
 *
 * Both for the reasons `scale-budgets.test.ts` sets out at length and does not
 * need repeating: this repository does not gate a PR on wall-clock, because a
 * shared runner does not get uniformly slower, it gets PREEMPTED, and a preempted
 * sample has no upper bound. A ratio cancels the machine, and the fastest of n
 * samples is the one statistic a loaded runner cannot inflate.
 *
 * ## The positive control is not optional here
 *
 * Every assertion below is of the form "this ratio is small", and the failure
 * mode of the harness is a ratio of 1.0 for everything — two measurements taken
 * against the same store, a corpus that did not grow, a read that returned
 * nothing at either size. All of those pass every flatness assertion.
 * `severitySummary` is the control: it is an all-time aggregate over every
 * finding, so it IS linear in the store BY DESIGN, and its ratio is asserted to
 * be LARGE. If that goes flat, the harness has stopped measuring growth and every
 * other case in this file is worthless.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteFindingsRepository } from '../../src/repositories/findings.ts';
import { SqliteSecurityRepository } from '../../src/repositories/security.ts';
import type { GeneratedCaptureCorpus } from '../helpers/corpus.ts';
import { corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const SMALL_EVENTS = 2_000;
const LARGE_EVENTS = 20_000;

/**
 * Real per-event spacing: 74,528 ms, measured on a real `~/.aka/data/aka.db`
 * (16,390 capture events spanning 14.1 days).
 *
 * **It does NOT make the 30-day window bind at these sizes, and an earlier
 * version of this comment claimed it did.** The arithmetic follows from the
 * measurement it cites: 20,000 x 74,528 ms is 17.25 days, so the whole large
 * corpus sits inside a 30-day window, exactly as it does at the generator's 1 s
 * default. Crossing that boundary needs **34,779** events, and a later change
 * raising `LARGE_EVENTS` past it would silently alter the experiment rather than
 * fail — which is the reason to write the number down.
 *
 * What holds `mttrTrend`'s answer fixed here is `RESOLUTION_TARGET`, not the
 * window. So this constant earns its place for a narrower reason than the one it
 * used to give: it keeps the corpus's TIMESTAMPS plausible, so the reads run
 * against a shape a real store could present, and it stops the two corpora
 * differing in density as well as in size. Do not cite it as a windowing bound.
 */
const REAL_SPACING_MS = 74_528;

/** Events needed for a corpus to outlast a 30-day window at `REAL_SPACING_MS`. */
const WINDOW_SPANNING_EVENTS = Math.ceil((30 * 86_400_000) / REAL_SPACING_MS);

/** Resolutions both corpora carry, so the ANSWER size is what stays fixed. */
const RESOLUTION_TARGET = 120;

/**
 * Trackable findings per event, used only to aim `resolutionRate` at
 * `RESOLUTION_TARGET`.
 *
 * Measured, not derived: at the default finding rate about a third of captures
 * carry a finding and about a quarter of captures are `code_change`, and the
 * product of two seeded draws is not worth predicting in closed form. Read off a
 * 4,000-event corpus (319 trackable) and cross-checked at 40,000. It only has to
 * be close — `RESOLUTION_TOLERANCE` is what makes being wrong loud instead of
 * silent.
 */
const TRACKABLE_PER_EVENT = 0.08;

/** How far the two resolution counts may differ before the experiment is void. */
const RESOLUTION_TOLERANCE = 0.35;

/**
 * A flat read may not cost more than this multiple at ten times the store.
 *
 * The same ceiling `scale-budgets.test.ts` uses, and for the same reason: a cost
 * that went linear in the store reads ~10x at a 10x step, so 3 sits with wide
 * margin on both sides of the boundary it has to separate. Measured ratios for
 * the three reads below are in the test names' own failure messages.
 */
const FLATNESS_CEILING = 3;

/**
 * The control must exceed this, or the harness is not measuring growth.
 *
 * `severitySummary` is linear in findings, which scale with events, so its true
 * ratio is ~10. Asserting only 2 leaves room for a runner where the constant
 * overhead is a larger share of the small measurement, while still being
 * unreachable by a harness that has gone flat.
 */
const CONTROL_FLOOR = 2;

/**
 * A gross-regression backstop, for the defect a ratio is structurally blind to.
 *
 * A cost that becomes 500 ms at EVERY size keeps a ratio of 1.0 and passes every
 * flatness assertion here. This is orders of magnitude above the measured costs
 * (single-digit ms at 20k) and is sized against `/security`'s own 2,000 ms budget
 * rather than tuned to a measurement, so it cannot flake on a preempted sample.
 * It is not the flatness guard and neither substitutes for the other.
 */
const GROSS_REGRESSION_MS = 500;

const SAMPLES = 25;
/**
 * The hook's ceiling. Nothing is measured against it — it exists so a slow seed
 * on a contended runner is not reported as a test timeout, which reads as a
 * budget failure and is not one.
 *
 * **Sized for THIS file's work rather than copied**, which is the mistake it
 * corrects. It was 120,000 ms, taken from `scale-budgets.test.ts`, whose hook
 * does substantially less: measured here at 3.53 s of hook time against that
 * file's 1.42-1.92 s for the nominally identical 2k + 20k pair. The difference
 * is the corpus, not the sampling — 3,119 ms of seeding against 539 ms of
 * samples — because this file needs the generator's measured 0.33 finding rate
 * and writes resolution rows, where that one pins 0.1 and writes none.
 *
 * At the ~30x macOS-CI factor `scale-budgets` derives, 3.53 s lands near 106 s:
 * inside 120,000 ms by about 12%, which a single preemption erases. That file
 * has already overrun this same ceiling once, at 135,237 ms.
 *
 * **Cutting the corpus is the usual remedy and is not available here**, so the
 * ceiling moves instead. `findingRate` cannot come down: at 0.1 the small corpus
 * holds 191 findings and `recentFindings` returns 191 rows against the large
 * corpus's 500, so the two sides would measure different amounts of work and the
 * ratio would stop meaning anything. And 2k -> 20k is already the cheapest pair
 * giving a 10x separation. Raising a ceiling that asserts nothing is not the same
 * act as relaxing a budget that does.
 */
const SEED_TIMEOUT_MS = 240_000;

/** The fastest of `samples` — the estimator note in the file header says why. */
function fastest(samples: number[]): number {
  return Math.min(...samples);
}

/**
 * `SAMPLES` timings of the read's SYNCHRONOUS work.
 *
 * Every repository method here runs its SQL synchronously and returns an
 * already-resolved promise, so the elapsed time around the bare call is the
 * whole of the work and the promise is never awaited. (That same fact is why
 * `/security`'s `Promise.all` buys nothing and the page costs the SUM of its
 * reads rather than the max.)
 *
 * The rejection is CAUGHT rather than discarded, and the reason is diagnostic
 * rather than cosmetic. A bare `void promise` that rejects is an unhandled
 * rejection — one per sample, 25 per read — and vitest may attribute that to an
 * unrelated test, so a broken read here would fail somewhere else in the suite
 * instead of failing as the clean assertion this file exists to give.
 *
 * The `catch` is deliberately EMPTY, and that is not a swallowed error: what
 * surfaces a broken read is the awaited `run[name]()` in `seedAndMeasure`, which
 * runs before any sampling and rejects the `beforeAll` with the read's own error.
 * Collecting the rejection here and rethrowing it after the loop looks stronger
 * and cannot work — a `.catch` callback runs in a MICROTASK, so it has not fired
 * by the time a synchronous loop finishes, and the check would read `undefined`
 * every time. That exact dead code was written here first, and what caught it was
 * fault-injecting a read that rejects only after its first call: the suite stayed
 * green through all 8 cases.
 */
function measure(fn: () => Promise<unknown>): number[] {
  const out: number[] = [];
  for (let i = 0; i < SAMPLES; i += 1) {
    const started = performance.now();
    void fn().catch(() => {
      // See above: the awaited call in `seedAndMeasure` is what reports a broken
      // read. This exists only so a rejection is never unhandled.
    });
    out.push(performance.now() - started);
  }
  return out;
}

interface Scale {
  readonly corpus: GeneratedCaptureCorpus;
  /** Rows each read returned — a read that returns nothing measures nothing. */
  readonly returned: Record<string, number>;
  readonly samples: Record<string, number[]>;
}

const READS = ['recentFindings', 'recentlyResolved', 'mttrTrend', 'severitySummary'] as const;
type ReadName = (typeof READS)[number];

async function seedAndMeasure(store: OwnedTempStore, events: number): Promise<Scale> {
  const db = store.open();
  const corpus = seedCaptureCorpus(db, {
    events,
    spacingMs: REAL_SPACING_MS,
    resolutionRate: Math.min(1, RESOLUTION_TARGET / (events * TRACKABLE_PER_EVENT)),
  });
  const raw = corpusConnection(db);
  // Both sizes measured in the same STATE. `seedCaptureCorpus` commits the whole
  // corpus in one transaction and a checkpoint cannot run inside one, so the log
  // is left holding the entire seed rather than the ~4.2 MB steady state a real
  // store settles at — measured at 4.13 MB for 2,000 events against 17.64 MB for
  // 20,000. Every read below then pays a log-proportional cost on one side only,
  // which is free while those pages are cached and is not on a runner executing
  // the whole workspace suite. Its sibling `scale-budgets.test.ts` failed CI on
  // exactly that, at a ratio of 3.619 on a commit that touched no product code;
  // the reasoning is written out there and not repeated.
  raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const findings = new SqliteFindingsRepository(raw);
  // The corpus's own clock, never `Date.now()`: the corpus is stamped from a
  // fixed 2024 epoch, so on the wall clock every windowed read is years past its
  // data and matches nothing — while still running, and still returning a
  // number, which is the failure this file could not detect from the outside.
  const security = new SqliteSecurityRepository(raw, () => corpus.endsAt);

  // Each entry runs the read and reports how many rows it produced. The COUNT is
  // awaited once per read and the TIMING never is: every method here runs its SQL
  // synchronously and hands back an already-resolved promise, so the elapsed time
  // around the bare call is the whole of the work. (That same fact is why
  // `/security`'s `Promise.all` buys nothing and the page costs the SUM of its
  // reads rather than the max.)
  //
  // Awaiting is not optional for the count, and the reason cost this file a bug:
  // a `.then` callback runs in a MICROTASK even on an already-resolved promise,
  // so reading the row count out of one and returning synchronously always yields
  // zero. That shipped here first time round, and what caught it was the vacuity
  // case below rather than review — every flatness ratio was a clean 1.00,
  // because zero rows cost the same at both sizes.
  // Each entry reports how many rows the read MATCHED — a number that must go to
  // zero when the read finds nothing, or the vacuity check below cannot fire.
  //
  // `mttrTrend` is the one where the obvious metric is a trap, and it shipped
  // here first time round: it returns `points`, which is
  // `Array.from({ length: numBuckets })` — 30 for a '30d' range — whether or not
  // a single finding matched. So `points.length` is the CONSTANT 30, and a
  // corpus seeding zero countable resolutions still reported 30 while every
  // bucket held null. Verified: at 2,000 events with `resolutionRate: 0` the read
  // returns 30 points and 0 non-null buckets. Counting non-null buckets is what
  // makes the guard mean "this read found something".
  const run: Record<ReadName, () => Promise<number>> = {
    recentFindings: async () => (await findings.recentFindings({ limit: 500 })).length,
    recentlyResolved: async () => (await security.recentlyResolved(20)).items.length,
    mttrTrend: async () =>
      (await security.mttrTrend('30d')).points.filter((point) =>
        Object.values(point.bySeverity).some((mean) => mean !== null),
      ).length,
    severitySummary: async () => (await security.severitySummary()).total,
  };

  const returned: Record<string, number> = {};
  const samples: Record<string, number[]> = {};
  for (const name of READS) {
    returned[name] = await run[name]();
    samples[name] = measure(run[name]);
  }
  return { corpus, returned, samples };
}

describe(`/security read costs from ${SMALL_EVENTS.toLocaleString('en-US')} to ${LARGE_EVENTS.toLocaleString('en-US')} events`, () => {
  let smallStore: OwnedTempStore;
  let largeStore: OwnedTempStore;
  let small: Scale;
  let large: Scale;

  beforeAll(async () => {
    smallStore = createTempStore('aka-security-scale-small-');
    largeStore = createTempStore('aka-security-scale-large-');
    small = await seedAndMeasure(smallStore, SMALL_EVENTS);
    large = await seedAndMeasure(largeStore, LARGE_EVENTS);
  }, SEED_TIMEOUT_MS);

  afterAll(() => {
    smallStore.destroy();
    largeStore.destroy();
  });

  it('both corpora are at the stated scale, and ten times apart', () => {
    expect(small.corpus.events).toBe(SMALL_EVENTS);
    expect(large.corpus.events).toBe(LARGE_EVENTS);
    // Findings are what three of these reads are linear in, so the SIZE step has
    // to be visible there too — a corpus that grew its events and not its
    // findings would leave every ratio below flat for the wrong reason.
    expect(large.corpus.findings / small.corpus.findings).toBeGreaterThan(5);
  });

  it('the two corpora carry the same number of resolutions, so only the store grew', () => {
    const a = small.corpus.resolutions;
    const b = large.corpus.resolutions;
    expect(a, 'small corpus seeded no resolutions').toBeGreaterThan(0);
    expect(b, 'large corpus seeded no resolutions').toBeGreaterThan(0);
    // The whole experiment rests on this. If the counts diverge, the reads that
    // are linear in RESOLUTIONS grow for a legitimate reason and their ratios
    // stop testing the store at all — so this fails rather than being reported
    // alongside a green flatness assertion.
    const skew = Math.abs(a - b) / Math.max(a, b);
    expect(
      skew,
      `resolution counts drifted apart (${String(a)} vs ${String(b)}); ` +
        'TRACKABLE_PER_EVENT needs re-measuring — the flatness cases below would ' +
        'otherwise be measuring resolution growth rather than store growth',
    ).toBeLessThan(RESOLUTION_TOLERANCE);
  });

  it('the corpus sits inside the 30-day window, so no case may claim the window bounds it', () => {
    // Pinned as a fact rather than left in prose, because it is the assumption
    // `REAL_SPACING_MS` used to state backwards. Every case here holds its
    // answer fixed through RESOLUTION_TARGET and the LIMITs, never through the
    // window — and if a later change raises LARGE_EVENTS past the boundary, the
    // windowed reads start shrinking and the experiment quietly becomes a
    // different one. This fails first and names the number.
    expect(
      LARGE_EVENTS,
      `LARGE_EVENTS has passed ${String(WINDOW_SPANNING_EVENTS)}, so the 30-day window now ` +
        'excludes part of the corpus. That changes what the windowed reads measure; re-read the ' +
        'note on REAL_SPACING_MS before raising the ceiling on this assertion.',
    ).toBeLessThan(WINDOW_SPANNING_EVENTS);
  });

  it('every read returns rows at both sizes, and the samples describe real work', () => {
    for (const name of READS) {
      // A read matching nothing is the vacuity this whole file is exposed to:
      // its cost would be flat at every size and every assertion below would
      // pass while measuring an empty result.
      expect(small.returned[name], `${name} returned nothing at the small size`).toBeGreaterThan(0);
      expect(large.returned[name], `${name} returned nothing at the large size`).toBeGreaterThan(0);
      expect(fastest(small.samples[name] ?? []), `${name} small floor`).toBeGreaterThan(0);
      expect(fastest(large.samples[name] ?? []), `${name} large floor`).toBeGreaterThan(0);
    }
  });

  for (const name of ['recentFindings', 'recentlyResolved', 'mttrTrend'] as const) {
    it(`${name} stays flat as the store grows`, () => {
      const smallest = fastest(small.samples[name] ?? []);
      const largest = fastest(large.samples[name] ?? []);
      const ratio = largest / smallest;
      expect(
        ratio,
        `${name} fastest-of-${String(SAMPLES)} was ${smallest.toFixed(3)} ms at ` +
          `${SMALL_EVENTS.toLocaleString('en-US')} events and ${largest.toFixed(3)} ms at ` +
          `${LARGE_EVENTS.toLocaleString('en-US')} — ratio ${ratio.toFixed(2)} against a ceiling ` +
          `of ${String(FLATNESS_CEILING)}. A cost that went linear in the store reads ~10x here.`,
      ).toBeLessThan(FLATNESS_CEILING);
      expect(largest, `${name} gross-regression backstop`).toBeLessThan(GROSS_REGRESSION_MS);
    });
  }

  it('the control grows: severitySummary is linear in findings by design', () => {
    const smallest = fastest(small.samples.severitySummary ?? []);
    const largest = fastest(large.samples.severitySummary ?? []);
    const ratio = largest / smallest;
    // Without this the file cannot tell a genuinely flat read from a harness that
    // measures the same store twice, and every case above passes either way.
    expect(
      ratio,
      `severitySummary was ${smallest.toFixed(3)} ms at ${SMALL_EVENTS.toLocaleString('en-US')} ` +
        `events and ${largest.toFixed(3)} ms at ${LARGE_EVENTS.toLocaleString('en-US')} — ratio ` +
        `${ratio.toFixed(2)}, which must exceed ${String(CONTROL_FLOOR)}. This read is an ` +
        'all-time aggregate over every finding, so a FLAT result here means the harness has ' +
        'stopped measuring store growth and every flatness case above is vacuous.',
    ).toBeGreaterThan(CONTROL_FLOOR);
  });
});
