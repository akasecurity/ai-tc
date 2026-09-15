/**
 * Whether `/security`'s ninth read stays flat as `capture_status` history
 * accumulates.
 *
 * `hot-read-query-plans.test.ts` registers the read and pins its plan, and the
 * plan is a clean indexed SEARCH at every store size — which is precisely why
 * that file cannot be the guard here. The generated `source_tool` column is in
 * no index (`idx_audit_type_t` is `(event_type, started_at)`), so for a site
 * with NO rows the seek has to examine the whole `capture_status` range before
 * it can conclude there is nothing to find. That is an indexed SEARCH in the
 * plan text and linear in the store in practice, and a single web chat is the
 * common shape: a user of one of the two sites pays the miss on every render.
 * And it is unbounded in the long run, because `audit_events` carries no
 * retention policy.
 *
 * What holds it is the read's recency window (`CAPTURE_STATUS_RECENCY_MS`): the
 * `started_at >= ?` predicate turns the range into an index range, so the seek
 * examines the reports inside the window instead of every report ever written.
 * The bound is on the WINDOW, not on the store, so this file states the
 * property that way — flat in HISTORY at a fixed reporting rate, which is how
 * these rows really accrue (a tab relays about two per open).
 *
 * A RATIO across two sizes rather than a millisecond budget, for the reason
 * `scale-budgets.test.ts` gives at length: an absolute bound on a
 * sub-millisecond quantity is a statement about the runner, and a preempted
 * sample has no upper bound. Everything the two sides share cancels. The
 * estimator is the FASTEST of n for the same reason: noise mostly adds time,
 * so a minimum is the statistic a loaded runner inflates LEAST. Not one it
 * cannot inflate: the section below records a round where load lifted it.
 *
 * ## The read is a constant plus a per-row term, and only a FACTOR cancels
 *
 * The site that has rows is answered by the `LIMIT`: its seek stops after
 * `STATUS_LOOKBACK_ROWS` rows, and each of those is parsed through the
 * attribute schema in JavaScript. That makes the CONSTANT, `c`: roughly
 * 0.7-1.0 ms for 128 rows with coverage instrumentation on (which is how this
 * package's `vitest run` always runs) across the sessions measured here, and
 * most of it is that parse: 0.61 ms, or 0.13 ms with coverage off. The site
 * with no rows is the PER-ROW term, `r`: SQLite tests `source_tool` on every
 * row in the range, 0.17-0.23 us a row on arm64 macOS across those sessions,
 * and coverage does not touch it.
 *
 * So the unbounded read's ratio across `S` and `L` rows is
 * `(c + L*r) / (c + S*r)`. A runner that is uniformly slower scales `c` and `r`
 * together and leaves it alone; anything that raises `c` AGAINST `r` pulls it
 * toward 1 while the per-row cost is unchanged. Raising `STATUS_LOOKBACK_ROWS`
 * does that in proportion to the rows it fetches, and so does a runner whose
 * JavaScript is slower relative to its SQLite. At 2,000 against 20,000 rows
 * the control read 3.7-4.4x on arm64 macOS across sessions, and one Linux x64
 * CI run read 5.024 ms against 14.143 ms: 2.8x, under the ceiling. Fitted to
 * that single run, `c` was ~4.0 ms against ~0.5 us a row, and one run cannot
 * say whether that proportion belongs to the runner or to one lifted minimum.
 * Load can lift a minimum: one round under 16 CPU burners on 8 cores raised
 * the small side 1.7x and read that old pair at 2.4x.
 *
 * At this file's pair, 2,000 and 50,000 rows, arm64 macOS / Node 24, coverage
 * on: the unbounded read is 1.13-1.20 ms against 10.0-12.3 ms, 8.7-10.2x, and
 * the windowed read 0.92-0.97x; under 16 CPU burners on 8 cores, 8.7-10.9x and
 * 0.88-0.95x, with one lifted round at 5.6x. Deleting the window turns the
 * flatness case red at 8.5-9.1x. On the proportion fitted to the CI run above,
 * this pair would read ~5.8x and reach 3 only once `c` was ~11 ms. Re-take
 * these when `STATUS_LOOKBACK_ROWS` grows or the per-row parse gets materially
 * heavier (a nested structure, not one more enum field): either moves `c`, and
 * nothing else in this file says so until a runner with a worse proportion
 * goes red.
 */
import type { DatabaseSync } from 'node:sqlite';

import { toCaptureStatusAttributes } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteCaptureStatusRepository } from '../../src/repositories/capture-status.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

/**
 * The two store sizes, seeded once and read by both cases.
 *
 * The separation the control needs comes from the LARGER one. The constant
 * already dominates the small side, so taking it below 2,000 rows barely moves
 * the ratio: in three sessions with coverage on, each seeding all four sizes in
 * one test, 500 rows against 20,000 read 4.6-5.0x where 2,000 read 3.9-4.1x.
 * Below ~2,000 rows the read also grows more slowly than the header's per-row
 * term predicts (500 to 2,000 rows added ~0.15 ms, about 0.1 us a row), so that
 * model is only approximate there. Every row added to the large side, by
 * contrast, is per-row cost the constant cannot absorb. Seeding 50,000 rows
 * takes ~0.7 s on arm64 macOS and 1-3.6 s under load, which is why it happens
 * once, in a `beforeAll`, rather than per case.
 */
const SMALL_ROWS = 2_000;
const LARGE_ROWS = 50_000;

/**
 * Reports per day, held constant across both sizes so the larger store is a
 * LONGER history rather than a busier one. That is the shape the window is
 * claimed to bound: more history at the same reporting rate leaves the same
 * number of reports inside the window.
 */
const REPORTS_PER_DAY = 4;
const DAY_MS = 86_400_000;

/** Enough samples for a stable minimum without making the file slow. */
const SAMPLES = 25;

/**
 * Ratio ceiling. 3, matching every other ratio gate in this directory: flat
 * reads measure near 1, and the unbounded form measured 5.6-10.9x at these
 * sizes on arm64 macOS, the low end a single round under heavy load. That range
 * depends on the pair and on the read's constant — see the header.
 */
const FLATNESS_CEILING = 3;

interface Corpus {
  readonly store: OwnedTempStore;
  readonly raw: DatabaseSync;
  /** The instant the newest row was written at — the corpus's own clock. */
  readonly endsAt: number;
}

const stores: OwnedTempStore[] = [];

/**
 * `rows` capture_status reports for ONE site, stamped backwards from a fixed
 * instant at `REPORTS_PER_DAY`.
 *
 * The site is always `chatgpt`; the read under test asks for `claude-ai`, which
 * has none. That is the miss, and the miss is the case that was linear. The
 * hit is answered by the LIMIT after `STATUS_LOOKBACK_ROWS` rows, a cost that
 * does not grow with history: it is the constant the header describes.
 */
function seedCorpus(rows: number): Corpus {
  const store = createTempStore('aka-capture-scale-', { migrated: true });
  stores.push(store);
  const raw = store.openRaw();

  const endsAt = Date.parse('2026-01-01T00:00:00.000Z');
  const step = DAY_MS / REPORTS_PER_DAY;
  const attributes = JSON.stringify(
    toCaptureStatusAttributes(
      {
        patched: true,
        live: false,
        blind: false,
        sendsSeenDom: 0,
        exchangesSeenNet: 0,
        parseFailures: 0,
        unparsedBodies: 0,
        shapeMisses: [],
        conversationEndpoints: 1,
        closed: false,
      },
      'chatgpt',
    ),
  );

  raw.exec('BEGIN');
  const insert = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, attributes) VALUES (?, ?, ?, ?)`,
  );
  for (let i = 0; i < rows; i += 1) {
    insert.run(`capture-status-${String(i)}`, 'capture_status', endsAt - i * step, attributes);
  }
  raw.exec('COMMIT');

  // The whole corpus commits in one transaction, so the log it leaves is the
  // seed's entire page footprint rather than the steady state — and it is
  // proportional to the corpus, so it lands on one side of the ratio only.
  // Checkpointing puts both stores in the same state, exactly as
  // `scale-budgets.test.ts` and `security-page-scale.test.ts` do.
  raw.exec('PRAGMA wal_checkpoint(TRUNCATE)');

  const seeded = (raw.prepare(`SELECT COUNT(*) AS n FROM audit_events`).get() as { n: number }).n;
  expect(seeded, `seeded ${String(rows)} rows but the store holds ${String(seeded)}`).toBe(rows);

  return { store, raw, endsAt };
}

/** The fastest of `SAMPLES` runs of `fn`, in milliseconds. */
function fastest(fn: () => void): number {
  let best = Infinity;
  for (let i = 0; i < SAMPLES; i += 1) {
    const started = process.hrtime.bigint();
    fn();
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    if (elapsed < best) best = elapsed;
  }
  return best;
}

afterAll(() => {
  for (const store of stores) store.destroy();
});

describe('capture-status read scale', () => {
  let small: Corpus;
  let large: Corpus;

  // Reads never write, so one pair serves both cases — which is also what lets
  // the control say it measures the SAME stores the flatness case does.
  beforeAll(() => {
    small = seedCorpus(SMALL_ROWS);
    large = seedCorpus(LARGE_ROWS);
  });

  it('is flat in store history at a fixed reporting rate', () => {
    const smallRepo = new SqliteCaptureStatusRepository(small.raw);
    const largeRepo = new SqliteCaptureStatusRepository(large.raw);

    // Read at the corpus's own clock, never `Date.now()`: the rows are stamped
    // from a fixed 2026 instant, so the wall clock would put every one of them
    // outside the window and both sides would measure an empty range — a real
    // number, for a read the product never performs, reported as flat.
    const smallMs = fastest(() => void smallRepo.latest(small.endsAt));
    const largeMs = fastest(() => void largeRepo.latest(large.endsAt));

    expect(
      largeMs / smallMs,
      `capture-status read grew with history: ${smallMs.toFixed(3)} ms at ${String(
        SMALL_ROWS,
      )} rows against ${largeMs.toFixed(3)} ms at ${String(LARGE_ROWS)}`,
    ).toBeLessThan(FLATNESS_CEILING);
  });

  it('the same read WITHOUT the recency window is linear — the control', () => {
    // The positive control, and the reason the case above is worth its green:
    // a ratio near 1 means nothing unless the same harness can produce one that
    // is not. Reading at an instant far enough past the corpus that the window
    // covers every row reproduces the unbounded read exactly, on the same
    // stores, through the same repository and the same statement.
    //
    // It is also the mutation test, standing: delete the `started_at >= ?`
    // predicate and the case above becomes this one, and goes red.
    const smallRepo = new SqliteCaptureStatusRepository(small.raw);
    const largeRepo = new SqliteCaptureStatusRepository(large.raw);

    // Far enough back that `now - CAPTURE_STATUS_RECENCY_MS` precedes the
    // OLDEST row in the larger corpus, so the predicate excludes nothing.
    const spanMs = (LARGE_ROWS / REPORTS_PER_DAY) * DAY_MS;
    const unbounded = (endsAt: number): number => endsAt - spanMs;

    const smallMs = fastest(() => void smallRepo.latest(unbounded(small.endsAt)));
    const largeMs = fastest(() => void largeRepo.latest(unbounded(large.endsAt)));

    expect(
      largeMs / smallMs,
      `the unbounded read did not grow with history (${smallMs.toFixed(3)} ms against ${largeMs.toFixed(
        3,
      )} ms), so this file cannot see the cost it exists to bound`,
    ).toBeGreaterThan(FLATNESS_CEILING);
  });
});
