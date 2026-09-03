/**
 * The `/activity` reads whose cost must NOT grow with the store, asserted as a
 * ratio across two store sizes — the experiment `findings-page-scale.test.ts`
 * runs for `/findings`, on the activity page's own corpus.
 *
 * ## Why every read here can be flat
 *
 * Each read the page makes on load asks a bounded question: `stats` counts
 * today and the sessions live in the last thirty minutes, the list is one page
 * of a window, the token chip folds a window, and the detail pane reads one
 * session. None of those questions grows as older history accumulates behind
 * it, so none of the reads may either.
 *
 * The one that did was the `liveNow` counter. For every open root it walked
 * every descendant to find the latest one — and on a real store EVERY root is
 * open, because the local writer never stamps `ended_at` on a session root. So
 * "sessions live in the last thirty minutes" read the whole table, and slowed
 * down with every day of history. This file is what keeps it a read of the last
 * thirty minutes.
 *
 * ## What holds the answer fixed
 *
 * `seedActivityCorpus` with `endedRate: 0` — the real shape, every root open —
 * and a fixed-size giant session at both sizes, so the detail read asks the
 * same question of both stores. Capture spacing is fixed, so a window both
 * stores hold in full has the same rows at both sizes, and sessions are
 * `captures / 40` at both, so the number of roots grows with the store the way
 * it does in the field. Sizes are captures (three rows each), and the pair is
 * sized against the ~30x CI-to-local seeding factor the security scale test
 * documents: 5k + 50k seed in about two seconds here.
 *
 * ## The control
 *
 * The all-time token report folds every `llm_call` in the store and must grow;
 * flat there means the harness has stopped measuring growth and every other
 * case is worthless.
 *
 * Fastest-of-n, as a ratio, for the reasons `scale-budgets.test.ts` sets out.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteActivityRepository } from '../../src/repositories/activity.ts';
import type { ActivityCorpus } from '../helpers/activity-corpus.ts';
import { seedActivityCorpus } from '../helpers/activity-corpus.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const SMALL_CAPTURES = 5_000;
const LARGE_CAPTURES = 50_000;

/**
 * The window the list and the token chip are read over. Three days rather than
 * the page's default seven because the SMALL corpus, at the real capture
 * spacing, spans only 4.3 days: a window both stores hold in full is what makes
 * the two reads answer the same-sized question.
 */
const WINDOW_DAYS = 3;

/** The giant session's size at BOTH sizes — what makes the detail read's answer fixed. */
const GIANT_CAPTURES = 500;

const DAY_MS = 86_400_000;

/** A flat read may not cost more than this multiple at ten times the store. */
const FLATNESS_CEILING = 3;

/** The control must exceed this, or the harness is not measuring growth. */
const CONTROL_FLOOR = 2;

/** A gross-regression backstop — sized far above the measured milliseconds. */
const GROSS_REGRESSION_MS = 500;

const SAMPLES = 25;

/** The hook's ceiling — nothing is measured against it; see security-page-scale.test.ts. */
const SEED_TIMEOUT_MS = 240_000;

function fastest(samples: number[]): number {
  return Math.min(...samples);
}

/**
 * `SAMPLES` timings of the read's SYNCHRONOUS work — every method here runs
 * its SQL synchronously and returns an already-resolved promise, so the
 * elapsed time around the bare call is the whole of the work. See the note of
 * the same name in security-page-scale.test.ts for the empty catch.
 */
function measure(fn: () => Promise<unknown>): number[] {
  const out: number[] = [];
  for (let i = 0; i < SAMPLES; i += 1) {
    const started = performance.now();
    void fn().catch(() => {
      // The awaited call in `seedAndMeasure` reports a broken read; this only
      // keeps a rejection from being unhandled.
    });
    out.push(performance.now() - started);
  }
  return out;
}

const READS = ['stats', 'listFirstPage', 'tokenChip', 'sessionDetail', 'tokensAllTime'] as const;
type ReadName = (typeof READS)[number];

/** The page-load reads that must stay flat; `tokensAllTime` is the control. */
const FLAT_READS: readonly ReadName[] = ['stats', 'listFirstPage', 'tokenChip', 'sessionDetail'];

interface Scale {
  readonly corpus: ActivityCorpus;
  /** Rows each read ANSWERED with — a read that matches nothing measures nothing. */
  readonly matched: Record<string, number>;
  readonly samples: Record<string, number[]>;
}

async function seedAndMeasure(store: OwnedTempStore, captures: number): Promise<Scale> {
  const raw = corpusConnection(store.open());
  const corpus = seedActivityCorpus(raw, { captures, endedRate: 0, giantCaptures: GIANT_CAPTURES });
  // Both sizes measured in the same STATE — the seed's single transaction
  // leaves a log proportional to the corpus, and a checkpoint cannot run inside
  // one. `scale-budgets.test.ts` explains the ratio this once broke.
  raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  // The corpus's own end is the clock, so "today" and "live" hold rows.
  const activity = new SqliteActivityRepository(raw, () => corpus.endsAt);
  const windowStart = corpus.endsAt - WINDOW_DAYS * DAY_MS;

  const run: Record<ReadName, () => Promise<number>> = {
    stats: async () => {
      const s = await activity.stats('UTC');
      return s.liveNow + s.sessionsToday;
    },
    listFirstPage: async () =>
      (
        await activity.listSessions({
          from: new Date(windowStart).toISOString(),
          excludeEmpty: true,
          limit: 100,
        })
      ).items.length,
    tokenChip: async () => (await activity.tokenReports(windowStart)).length,
    sessionDetail: async () =>
      (await activity.getSession(corpus.largestSessionId))?.events.length ?? 0,
    tokensAllTime: async () => (await activity.tokenReports()).length,
  };

  const matched: Record<string, number> = {};
  const samples: Record<string, number[]> = {};
  for (const name of READS) {
    matched[name] = await run[name]();
    samples[name] = measure(run[name]);
  }
  return { corpus, matched, samples };
}

describe(`/activity read costs from ${SMALL_CAPTURES.toLocaleString('en-US')} to ${LARGE_CAPTURES.toLocaleString('en-US')} captures`, () => {
  let smallStore: OwnedTempStore;
  let largeStore: OwnedTempStore;
  let small: Scale;
  let large: Scale;

  beforeAll(async () => {
    smallStore = createTempStore('aka-activity-scale-small-', { migrated: true });
    largeStore = createTempStore('aka-activity-scale-large-', { migrated: true });
    small = await seedAndMeasure(smallStore, SMALL_CAPTURES);
    large = await seedAndMeasure(largeStore, LARGE_CAPTURES);
  }, SEED_TIMEOUT_MS);

  afterAll(() => {
    smallStore.destroy();
    largeStore.destroy();
  });

  it('both corpora are at the stated scale, and ten times apart', () => {
    expect(small.corpus.captures).toBe(SMALL_CAPTURES);
    expect(large.corpus.captures).toBe(LARGE_CAPTURES);
    expect(large.corpus.sessions / small.corpus.sessions).toBeGreaterThan(5);
  });

  it('every read answered with something at both sizes, so a ratio of 1 is not an empty scope', () => {
    for (const name of READS) {
      expect(
        small.matched[name],
        `${name} matched nothing at ${String(SMALL_CAPTURES)}`,
      ).toBeGreaterThan(0);
      expect(
        large.matched[name],
        `${name} matched nothing at ${String(LARGE_CAPTURES)}`,
      ).toBeGreaterThan(0);
    }
  });

  it('the flat reads answer the same-sized question at both sizes', () => {
    // A window holds the same captures at both sizes and the giant session is
    // the same size, so the answers must be of the same order — a large-side
    // count many times the small one would mean the scope leaked and the ratio
    // below is measuring the store after all.
    for (const name of FLAT_READS) {
      const a = small.matched[name] ?? 0;
      const b = large.matched[name] ?? 0;
      expect(b / a, `${name}: ${String(a)} matched at small, ${String(b)} at large`).toBeLessThan(
        FLATNESS_CEILING,
      );
    }
  });

  for (const name of FLAT_READS) {
    it(`${name} stays flat as the store grows`, () => {
      const smallest = fastest(small.samples[name] ?? []);
      const largest = fastest(large.samples[name] ?? []);
      const ratio = largest / smallest;
      expect(
        ratio,
        `${name} fastest-of-${String(SAMPLES)} was ${smallest.toFixed(3)} ms at ` +
          `${SMALL_CAPTURES.toLocaleString('en-US')} captures and ${largest.toFixed(3)} ms at ` +
          `${LARGE_CAPTURES.toLocaleString('en-US')} — a ratio of ${ratio.toFixed(3)} across a 10x ` +
          `size step, where a cost linear in the store would read ~10`,
      ).toBeLessThan(FLATNESS_CEILING);
      expect(largest, `${name} at ${LARGE_CAPTURES.toLocaleString('en-US')} captures`).toBeLessThan(
        GROSS_REGRESSION_MS,
      );
    });
  }

  it('the all-time token report grows with the store (the positive control)', () => {
    const smallest = fastest(small.samples.tokensAllTime ?? []);
    const largest = fastest(large.samples.tokensAllTime ?? []);
    const ratio = largest / smallest;
    expect(
      ratio,
      `tokensAllTime read ${smallest.toFixed(3)} ms at small and ${largest.toFixed(3)} ms at large — ` +
        `a ratio of ${ratio.toFixed(3)}. It folds every llm_call in the store and must grow; ` +
        `flat here means the harness is no longer measuring growth`,
    ).toBeGreaterThan(CONTROL_FLOOR);
  });
});
