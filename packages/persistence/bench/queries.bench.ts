/**
 * The dashboard's read surface at a stated store size.
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
 * | 50k        |                       159 ms | inside                         |
 * | 150k       |                       350 ms | inside                         |
 * | 300k       |                       729 ms | inside                         |
 * | 1M         |    ~2.5-3 s (extrapolated)   | **over**                       |
 *
 * The 1M row is NOT a measurement, and it is not a straight-line one either: the
 * page is mildly superlinear, so a two-point slope reads ~2.0 s and a fit over
 * all three reads 2.5-3 s. `severitySummary` is what bends it — 46.6 / 177.7 /
 * 472.2 ms, i.e. 0.93 / 1.19 / 1.57 us per event, a per-event cost rising ~1.33x
 * per doubling — and at 1M it is ~85% of the page on its own. Take the range as
 * the finding rather than either end.
 *
 * Nothing here reaches 1M because SEEDING does not scale: 142 s at 150k against
 * 733 s at 300k, 5.2x for 2x the events. A 1M corpus is tens of minutes, which is
 * why this file's largest measured point is 300k and why the row above is a fit.
 *
 * ## The figures this table replaced, and why they were wrong in BOTH directions
 *
 * The earlier sweep read 5,945 ms at 1M and 373 ms at 100k, crossing the budget
 * near 363k events. Those numbers were taken correctly and described the wrong
 * store, on two counts that pulled opposite ways:
 *
 *  - **Too pessimistic on density.** `spacingMs` was 1 s, so a million events
 *    spanned 11.6 days and a 30-day window held the WHOLE corpus — every windowed
 *    read cost what an unwindowed one does. No install does that.
 *  - **Far too optimistic on `recentlyResolved`**, which it recorded at 8 ms and
 *    called one of "the cheap two". The corpus wrote no `finding_resolution` rows
 *    at all, so that read was measured on an empty table. Seed resolutions and it
 *    is 10,966 ms at 50k events and 125,322 ms at 150k — QUADRATIC, since the plan
 *    enumerated every (code_change event x resolved key) pair. The page took 126
 *    SECONDS at 150k, not 5.9 s at 1M.
 *
 * Both are fixed: the generator now seeds resolutions and finding keys, and its
 * finding rate is a measured 0.33 rather than 0.1. `recentlyResolved`, `mttrTrend`
 * and `recentFindings` were rewritten to drive from the bounded side of their
 * joins, and `test/performance/security-page-scale.test.ts` pins all three as
 * ratios so a regression is a red test rather than a number in this comment.
 *
 * What remains is `severitySummary` — 65% of the page at 300k (472.2 ms of 729) and
 * ~85% of it by 1M, an all-time `GROUP BY` over every finding whose cost IS its
 * semantics. It is also why the budget is still missed at 1M after everything
 * above: bounding it is a product decision (a maintained rollup, windowing the
 * card, or retention on the corpus itself), not a tuning one.
 *
 * WHY THE CLOCK IS PINNED, and why it is the difference between a real number
 * and a comfortable one. Six of the eight filter on a window ending "now", and
 * the generator stamps its events from a fixed 2024 epoch so the corpus is
 * identical on every machine. Left on the wall clock the window sits years past
 * every row, six of the eight match NOTHING, and the same 1M store reported
 * 3,831 ms — inside half the cost measured then, from a run that looks perfectly
 * valid. A benchmark whose input is empty is the failure mode to watch for here,
 * and the retracted `recentlyResolved` figure above is the same mistake reached by
 * a different route: not an empty window, but an empty TABLE.
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
