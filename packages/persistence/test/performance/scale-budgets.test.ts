/**
 * The two per-call store costs that sit inside the hook's 10 s budget, asserted
 * against a store big enough that a cost which grew with it would show.
 *
 * A hook opens the store and writes one capture on every tool call, and a hook
 * that overruns its harness timeout is killed — which the harness reads as "no
 * opinion", letting the tool call through UNSCANNED. So these are not comfort
 * budgets; they are the margin between an audited call and a silent gap.
 *
 * ## Why these two are tests and `/security` is not
 *
 * This repository does not gate a PR on wall-clock — CI runners are too noisy,
 * a flaky gate gets ignored, and an ignored gate is worse than none. The
 * exception the repo already makes is an UPPER bound with real headroom, which
 * fails only on an algorithmic change: the ReDoS gate and the isolation ceilings
 * are both that shape. These two qualify by a wide margin, because both costs
 * are FLAT in the store size:
 *
 * | store size | `recordCapture` | `openLocalDatabase` |
 * | ---------- | --------------: | ------------------: |
 * | 10k events |       0.0958 ms |           0.5883 ms |
 * | 100k       |        0.088 ms |             0.56 ms |
 * | 1M         |        0.076 ms |             0.55 ms |
 *
 * The 10k row is the tinybench MEAN from `pnpm bench`; the other two are the
 * MEDIAN of the scale sweep (n=200 captures, n=20 opens). Different statistics
 * because they come from different harnesses — the point is the flatness, which
 * holds either way, not a fourth significant figure.
 *
 * against budgets of 30 ms and 100 ms — roughly 165× and 125× of headroom at a
 * million rows. A bound that generous cannot flake on a slow runner and cannot
 * pass a regression that made either cost scale with the table.
 *
 * `/security` gets no test here, and the omission is deliberate rather than an
 * oversight: it MISSES its 2,000 ms budget at 1M events (5,945 ms measured), so
 * there is no passing assertion to write. It is measured in `bench/queries.bench.ts`
 * and reported there.
 *
 * ## Why 100k rather than 1M
 *
 * A 1M-event corpus takes 10.7 minutes to build, which does not belong
 * in a test tier. 100k is the largest size a test tier can carry, and the table
 * above is what makes it sufficient: a regression that put either cost on the
 * table's size would already be visible at 100k, because the flatness being
 * guarded holds from 10k upward. The 1M end is exercised by hand.
 *
 * ## The corpus is built in a HOOK, under a SETUP-sized ceiling
 *
 * Seeding 100k events costs about 9.6 s on arm64 macOS against measured work of
 * roughly 40 ms — the setup is more than two orders of magnitude more expensive
 * than everything asserted. Two separate things follow, and only doing both
 * removes the flake:
 *
 * The seed lives in `beforeAll`, so the test's own budget covers the
 * measurement and nothing else. Left in the `it()` body it would spend almost
 * all of the 20 s `testTimeout` before the first sample. The body is
 * SYNCHRONOUS, so vitest cannot interrupt it: it runs to completion and is then
 * reported as a timeout, which reads as a budget failure and is not one.
 *
 * And the hook carries `SEED_TIMEOUT_MS` rather than the config's 20 s, because
 * moving the cost does not shrink it — 9.6 s under a 20 s hook ceiling is the
 * same 2x margin, and CI runners several times slower than this one are the
 * documented case. That ceiling bounds SETUP and asserts nothing; the two
 * budgets that are real measurements keep the defaults. Raising THOSE to answer
 * a red would be the mistake this file exists to avoid.
 *
 * ## What is asserted is a QUANTILE, not a mean or a max
 *
 * A mean hides a tail, and a single slowest sample is a GC pause or the OS
 * stealing the core — the measured max at 1M was 3.75 ms against a 0.086 ms
 * median, all of it scheduling. The p95 keeps the assertion about the code while
 * staying immune to one unlucky sample.
 */
import type { IngestEvent } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { openLocalDatabase } from '../../src/database.ts';
import type { GeneratedCaptureCorpus } from '../helpers/corpus.ts';
import { CORPUS_EPOCH_MS, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const CORPUS_EVENTS = 100_000;

/** The budgets, verbatim. */
const RECORD_CAPTURE_BUDGET_MS = 30;
const OPEN_DATABASE_BUDGET_MS = 100;

/**
 * The ceiling on CORPUS SETUP, distinct from the two budgets under test.
 *
 * A corpus is not a measurement, so this is sized for the slowest runner rather
 * than tuned: about 10 s of work on this machine, against a CI leg documented as
 * several times slower. Nothing is asserted against it — a hook that overran
 * would report a setup failure, which is what it would be.
 */
const SEED_TIMEOUT_MS = 180_000;

const CAPTURE_SAMPLES = 200;
const OPEN_SAMPLES = 20;

function p95(samples: number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1);
  return sorted[index] ?? Number.POSITIVE_INFINITY;
}

function makeEvent(seq: number): IngestEvent {
  return {
    id: `ffffffff-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date(CORPUS_EPOCH_MS + (CORPUS_EVENTS + seq) * 1_000).toISOString(),
    // Distinct per call: the capture row is content-addressed, so a shared hash
    // would turn every sample after the first into an upsert onto one row — a
    // cheaper path than the insert under test, and one that would keep this
    // green after the insert had regressed.
    contentHash: `budget-probe-${String(seq)}`,
    content: 'refactor the session handler so a retry never reopens the store',
    metadata: { sessionId: '22222222-2222-4222-8222-222222222222' },
  };
}

describe(`store costs at ${CORPUS_EVENTS.toLocaleString('en-US')} events`, () => {
  let store: OwnedTempStore;
  let db: LocalDatabase;
  let corpus: GeneratedCaptureCorpus;

  beforeAll(() => {
    store = createTempStore('aka-scale-budget-');
    db = store.open();
    // Throws unless the rows are on disk. Every assertion below is an upper
    // bound on time, and the fastest possible store is an empty one — so
    // without this the whole file would pass most convincingly at the moment
    // the corpus stopped being written.
    corpus = seedCaptureCorpus(db, { events: CORPUS_EVENTS, sessions: 200, seed: 1 });
  }, SEED_TIMEOUT_MS);

  afterAll(() => {
    store.destroy();
  });

  it('the corpus really is at the stated scale', () => {
    // Read back rather than trusted: the seed runs in a hook, so a body that
    // asserted nothing about it would time the store it happened to get.
    expect(corpus.events).toBe(CORPUS_EVENTS);
    expect(corpus.findings).toBeGreaterThan(0);
  });

  it('recordCapture and openLocalDatabase both stay inside their budgets', () => {
    const captures: number[] = [];
    for (let i = 0; i < CAPTURE_SAMPLES; i += 1) {
      const started = performance.now();
      db.recordCapture(makeEvent(i), []);
      captures.push(performance.now() - started);
    }

    const opens: number[] = [];
    for (let i = 0; i < OPEN_SAMPLES; i += 1) {
      const started = performance.now();
      const handle = openLocalDatabase(store.dataDir);
      opens.push(performance.now() - started);
      handle.close();
    }

    const capture95 = p95(captures);
    const open95 = p95(opens);

    expect(
      capture95,
      `recordCapture p95 was ${capture95.toFixed(3)} ms over ${String(CAPTURE_SAMPLES)} samples`,
    ).toBeLessThan(RECORD_CAPTURE_BUDGET_MS);
    expect(
      open95,
      `openLocalDatabase p95 was ${open95.toFixed(1)} ms over ${String(OPEN_SAMPLES)} samples`,
    ).toBeLessThan(OPEN_DATABASE_BUDGET_MS);

    // The samples must describe real work. A `performance.now()` that stopped
    // advancing, or a loop that never ran, reports 0 and satisfies both
    // bounds — the one way an upper-bound timing assertion goes vacuous.
    expect(captures.reduce((a, b) => a + b, 0)).toBeGreaterThan(0);
    expect(opens.reduce((a, b) => a + b, 0)).toBeGreaterThan(0);
  });
});
