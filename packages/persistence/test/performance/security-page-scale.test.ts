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
 * Real per-event spacing, so a 30-day window holds a FRACTION of the store.
 *
 * Measured on a real `~/.aka/data/aka.db`: 16,390 capture events spanning 14.1
 * days, i.e. 74,528 ms between events. At the generator's 1 s default a corpus
 * of any size fits inside a 30-day window, which makes every windowed read cost
 * exactly what an unwindowed one does — so `mttrTrend`'s window would bound
 * nothing here and the case would hold whether or not the fix worked.
 */
const REAL_SPACING_MS = 74_528;

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
const SEED_TIMEOUT_MS = 120_000;

/** The fastest of `samples` — the estimator note in the file header says why. */
function fastest(samples: number[]): number {
  return Math.min(...samples);
}

function measure(fn: () => void): number[] {
  const out: number[] = [];
  for (let i = 0; i < SAMPLES; i += 1) {
    const t = performance.now();
    fn();
    out.push(performance.now() - t);
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
  const run: Record<ReadName, () => Promise<number>> = {
    recentFindings: async () => (await findings.recentFindings({ limit: 500 })).length,
    recentlyResolved: async () => (await security.recentlyResolved(20)).items.length,
    mttrTrend: async () => (await security.mttrTrend('30d')).points.length,
    severitySummary: async () => (await security.severitySummary()).total,
  };

  const returned: Record<string, number> = {};
  const samples: Record<string, number[]> = {};
  for (const name of READS) {
    returned[name] = await run[name]();
    samples[name] = measure(() => void run[name]());
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
