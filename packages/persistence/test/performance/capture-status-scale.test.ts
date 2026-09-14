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
 *
 * Measured on the unbounded read: 0.331 ms at 2,000 rows against 4.389 ms at
 * 20,000 — 13.3x for 10x the rows — and unbounded in the long run because
 * `audit_events` carries no retention policy.
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
 * estimator is the FASTEST of n for the same reason — noise only ever adds
 * time, so a minimum is the one statistic a loaded runner cannot inflate.
 */
import type { DatabaseSync } from 'node:sqlite';

import { toCaptureStatusAttributes } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { SqliteCaptureStatusRepository } from '../../src/repositories/capture-status.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

/**
 * The two store sizes. Small, deliberately: what is under test is a ratio, and
 * a ratio needs no particular absolute size — the pair `scale-budgets.test.ts`
 * came down to, for the reason recorded there (a seed that overran its own hook
 * ceiling on CI at 3% margin).
 */
const SMALL_ROWS = 2_000;
const LARGE_ROWS = 20_000;

/**
 * Reports per day, held constant across both sizes so the larger store is a
 * LONGER history rather than a busier one. That is the shape the window is
 * claimed to bound: ten times the history at the same reporting rate leaves
 * the same number of reports inside the window.
 */
const REPORTS_PER_DAY = 4;
const DAY_MS = 86_400_000;

/** Enough samples for a stable minimum without making the file slow. */
const SAMPLES = 25;

/**
 * Ratio ceiling. 3, matching every other ratio gate in this directory: flat
 * reads measure near 1 and the linear form this exists to catch measures above
 * 10, so the ceiling sits in a wide gap rather than on a tuned edge.
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
 * has none. That is the miss, and the miss is the case that was linear — the
 * hit is answered by the LIMIT after a handful of rows and was flat all along.
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
        enforcement: 'watching',
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
  it('is flat in store history at a fixed reporting rate', () => {
    const small = seedCorpus(SMALL_ROWS);
    const large = seedCorpus(LARGE_ROWS);
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
    const small = seedCorpus(SMALL_ROWS);
    const large = seedCorpus(LARGE_ROWS);
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
