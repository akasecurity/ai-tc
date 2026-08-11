/**
 * The dashboard's read surface at a stated store size — and the one budget in
 * this package that is currently missed.
 *
 * `/security` renders eight aggregations. The page awaits them in a single
 * `Promise.all`, which reads like eight concurrent queries and is not: every
 * repository method here runs its SQL SYNCHRONOUSLY and hands back an
 * already-resolved promise, so `Promise.all` awaits eight settled values and the
 * page costs the SUM. Measured on arm64 macOS, Node 24, against a corpus with
 * the clock pinned to it:
 *
 * | store size | `/security` (8 aggregations) | verdict vs the 2,000 ms budget |
 * | ---------- | ---------------------------: | ------------------------------ |
 * | 100k       |            373 ms † (median) | inside                         |
 * | 200k       |                       963 ms | inside                         |
 * | 300k       |                     1,515 ms | inside                         |
 * | 500k       |                     2,964 ms | **over**                       |
 * | 1M         |          5,945 ms † (median) | **3.0× over**                  |
 *
 * † re-measured since, median of 5 (100k samples 356/357/373/390/392; 1M samples
 * 5905/5915/5945/7399/7418). The three middle rows are from the original sweep
 * and have not been re-taken — a `/security` figure is a wall clock, so treat
 * any single one as ±20% and the SHAPE as the finding.
 *
 * Growth is linear past 100k at 6.19 ms per additional thousand events (the slope
 * through the two re-measured endpoints), so the budget is crossed near 362,800
 * events — about 300 MB of store, well inside
 * what a year of daily use produces. Five of the eight are over a second each at
 * 1M (`enforcementActions` 2,079 ms, `findingsTimeseries` 1,227 ms,
 * `severitySummary` 1,191 ms, `mttrTrend` 1,164 ms, `recentFindings` 1,160 ms;
 * `topSources` 414 ms and `recentlyResolved` 8 ms are the cheap two), so no
 * single query is the culprit and no single index fixes it.
 *
 * It is not a missing index either: `test/performance/hot-read-query-plans.test.ts`
 * confirms every one of these runs indexed. That check runs at 3k, and nothing
 * re-captures the plans above it — SQLite has no `ANALYZE` statistics on this
 * store, so it plans from the schema rather than from row counts and the plans
 * are EXPECTED to be the same at 1M. The cost is
 * that four of them do not shrink with the window at all — `severitySummary`,
 * `recentFindings` and `recentlyResolved` take no range, and `mttrTrend`'s
 * `EXISTS` prefilter bounds the RESULT rather than the scan — while the rest of
 * the cost is that the windowed ones are bounded by a WINDOW rather than a limit, and the
 * corpus is dense enough that a 30-day window at 1M events still contains most
 * of the store. Fixing it means bounding what the page reads — a product
 * decision (retention, pre-aggregation, or a cap), not a tuning one.
 *
 * WHY THE CLOCK IS PINNED, and why it is the difference between a real number
 * and a comfortable one. Six of the eight filter on a window ending "now", and
 * the generator stamps its events from a fixed 2024 epoch so the corpus is
 * identical on every machine. Left on the wall clock the window sits years past
 * every row, six of the eight match NOTHING, and the same 1M store reports
 * 3,831 ms — inside half the real cost, from a run that looks perfectly valid.
 * A benchmark whose input is empty is the failure mode to watch for here.
 *
 * NO ASSERTIONS: nothing in this repository gates a PR on wall-clock. The
 * measurement above is a finding, recorded here so it is re-taken rather than
 * remembered.
 */
import { bench, describe } from 'vitest';

import { SqliteActivityRepository } from '../src/repositories/activity.ts';
import { SqliteFindingsRepository } from '../src/repositories/findings.ts';
import { SqliteSecretVaultRepository } from '../src/repositories/secret-vault.ts';
import { SqliteSecurityRepository } from '../src/repositories/security.ts';
import { corpusConnection, seedCaptureCorpus } from '../test/helpers/corpus.ts';
import type { OwnedTempStore } from '../test/helpers/temp-store.ts';
import { createTempStore } from '../test/helpers/temp-store.ts';

/**
 * 1M is absent for the same reason as in `capture.bench.ts`: 10.7 minutes of
 * corpus is too much for a nightly. The 1M row of the table above was taken by
 * hand against a store built once.
 */
const SCALES = [10_000, 100_000] as const;

/**
 * The scale the per-aggregation breakdown runs at. Indexed out of `SCALES` so
 * the two cannot drift: at 10k every aggregation is under 5 ms and the sampling
 * noise exceeds the signal, so the breakdown wants the larger one.
 */
const BREAKDOWN_SCALE = SCALES[1];

const DAY_MS = 86_400_000;

interface Surfaces {
  readonly store: OwnedTempStore;
  readonly security: SqliteSecurityRepository;
  readonly findings: SqliteFindingsRepository;
  readonly activity: SqliteActivityRepository;
  readonly vault: SqliteSecretVaultRepository;
  readonly now: number;
}

const fixtures = new Map<number, Surfaces>();

function fixtureFor(events: number): Surfaces {
  const existing = fixtures.get(events);
  if (existing) return existing;

  const store = createTempStore(`aka-bench-queries-${String(events)}-`);
  const db = store.open();
  const corpus = seedCaptureCorpus(db, { events, sessions: 200, seed: 1 });
  const raw = corpusConnection(db);

  // The corpus's own end, not the wall clock, and read off the corpus rather
  // than recomputed from a local copy of its epoch — see the header.
  const now = corpus.endsAt;
  const surfaces: Surfaces = {
    store,
    security: new SqliteSecurityRepository(raw, () => now),
    findings: new SqliteFindingsRepository(raw),
    activity: new SqliteActivityRepository(raw),
    vault: new SqliteSecretVaultRepository(raw),
    now,
  };
  fixtures.set(events, surfaces);
  return surfaces;
}

process.on('exit', () => {
  for (const { store } of fixtures.values()) {
    try {
      store.destroy();
    } catch {
      // Teardown of a benchmark fixture; a failure here has nothing to report to.
    }
  }
});

/** Exactly the eight the page awaits, in page order. */
async function securityPage(s: Surfaces): Promise<void> {
  await Promise.all([
    s.security.severitySummary(),
    s.security.enforcementActions('30d'),
    s.security.findingsTimeseries('30d'),
    s.security.mttrTrend('30d'),
    s.security.scanCoverage('30d'),
    s.security.topSources('30d', { limit: 5 }),
    s.security.recentlyResolved(),
    s.findings.recentFindings({ limit: 500 }),
  ]);
}

const PAGE_OPTIONS = { time: 0, iterations: 10, warmupIterations: 2, warmupTime: 0 };
const PART_OPTIONS = { time: 0, iterations: 20, warmupIterations: 3, warmupTime: 0 };

describe('/security — the whole eight-aggregation page', () => {
  for (const events of SCALES) {
    bench(
      `${events.toLocaleString('en-US')} events`,
      async () => {
        await securityPage(fixtureFor(events));
      },
      {
        ...PAGE_OPTIONS,
        setup: () => {
          fixtureFor(events);
        },
      },
    );
  }
});

describe(`/security — each aggregation on its own, at ${BREAKDOWN_SCALE.toLocaleString('en-US')} events`, () => {
  // The page total is the sum of these, so a regression in the total is only
  // actionable once it is attributed. Run at the larger scale only: at 10k every
  // one of them is under 5 ms and the sampling noise exceeds the signal.
  const PARTS: readonly [string, (s: Surfaces) => Promise<unknown>][] = [
    ['severitySummary', (s) => s.security.severitySummary()],
    ['enforcementActions', (s) => s.security.enforcementActions('30d')],
    ['findingsTimeseries', (s) => s.security.findingsTimeseries('30d')],
    ['mttrTrend', (s) => s.security.mttrTrend('30d')],
    ['topSources', (s) => s.security.topSources('30d', { limit: 5 })],
    ['recentlyResolved', (s) => s.security.recentlyResolved()],
    ['recentFindings', (s) => s.findings.recentFindings({ limit: 500 })],
    // `scanCoverage` is omitted: it returns a curated constant and reads no
    // table, so it would benchmark the promise machinery and nothing else.
  ];

  for (const [name, run] of PARTS) {
    bench(
      name,
      async () => {
        await run(fixtureFor(BREAKDOWN_SCALE));
      },
      {
        ...PART_OPTIONS,
        setup: () => {
          fixtureFor(BREAKDOWN_SCALE);
        },
      },
    );
  }
});

describe('/activity — the session list', () => {
  for (const events of SCALES) {
    bench(
      `${events.toLocaleString('en-US')} events`,
      async () => {
        const s = fixtureFor(events);
        await s.activity.listSessions({
          excludeEmpty: true,
          from: new Date(s.now - 30 * DAY_MS).toISOString(),
          limit: 100,
        });
      },
      {
        ...PART_OPTIONS,
        setup: () => {
          fixtureFor(events);
        },
      },
    );
  }
});

describe('/vault — the inventory listing', () => {
  // The corpus writes no vault rows (tokenization needs consent and a key), so
  // this measures the listing over an EMPTY vault against a full store: the
  // floor, not the loaded case. It is here because the query joins the
  // exceptions table per row and that join is what the reuse insight pays for
  // — a regression in the empty case is a regression in the shape.
  for (const events of SCALES) {
    bench(
      `${events.toLocaleString('en-US')} events, empty vault`,
      () => {
        const s = fixtureFor(events);
        s.vault.listInventory({}, s.now);
      },
      {
        ...PART_OPTIONS,
        setup: () => {
          fixtureFor(events);
        },
      },
    );
  }
});
