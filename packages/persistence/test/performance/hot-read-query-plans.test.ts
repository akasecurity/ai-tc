/**
 * How SQLite executes every read the four data-heavy dashboard pages issue.
 *
 * This is a CORRECTNESS assertion, not a timing one, which is why it is a test
 * rather than a benchmark. A query plan is a fact about the schema and the SQL:
 * it does not vary with the runner's load, so it can gate a PR without the
 * flakiness that rules wall-clock out.
 *
 * Two properties, and the second exists because the first cannot see the thing
 * that actually costs.
 *
 * **No hot read may pass over a table with no index at all** (`SCAN t`). That is
 * the criterion in the plainest form, and it holds today.
 *
 * **The full INDEX scans are pinned as an exact set.** `SCAN t USING INDEX i` is
 * not a defect — for a whole-table aggregate it is usually the best plan there
 * is — and it is USUALLY O(rows), so most of them are a place where the
 * dashboard gets slower as the store grows. Left unpinned, a new one could
 * appear and the first assertion would stay green, because the query would have
 * an index and would still visit every row. The set is compared EXACTLY, in both
 * directions: an entry that disappears fails too, so someone who adds an index
 * that turns a scan into a search is told to delete the line rather than leaving
 * a stale claim behind.
 *
 * **"Usually" is doing real work in that sentence, and the exception is why this
 * file cannot be the only guard.** A `SCAN` under a `LIMIT` whose order comes
 * from the index terminates early, and EXPLAIN QUERY PLAN prints it exactly like
 * one that does not — there is no plan text for "stops after 500 rows".
 * `recentFindings` is that case and is annotated at its entry. It means a reader
 * cannot infer growth from this set alone, in either direction: an entry may be
 * bounded, and a plan that looks ideal can still be linear in the store, which
 * is what `security-page-scale.test.ts` measures as a ratio across two sizes.
 *
 * **The plans are taken from the reads, never restated here.** `recordingConnection`
 * captures the SQL and the bound parameters as the repositories execute them; a
 * query spelled a second time in this file would be free to drift from the one
 * the dashboard runs, and a plan assertion over drifted SQL is a green that
 * describes nothing.
 *
 * WHY A CORPUS AT ALL, given plans are heuristic. Two reads only prepare their
 * statements on the path a row reaches (`getSession` fans out over a session's
 * events), so an empty store would exercise a fraction of the surface and the
 * pinned set would be a claim about the queries that happen to run against
 * nothing.
 *
 * WHY A SMALL ONE, and what that does NOT buy. The store carries no `ANALYZE`
 * statistics — nothing in this package runs it — so SQLite plans from the
 * schema rather than from row counts, and a 3k-event store is expected to yield
 * the same plans a 1M-event one does. That is the reasoning, not a measurement:
 * NOTHING here re-checks the plans at a larger scale. `scale-budgets.test.ts`
 * builds a 20k corpus but asserts only timings, and the 1M end is built by
 * hand. Say "expected" rather than "asserted" about any scale above 3k until
 * something in this directory actually captures the plans there.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { SqliteActivityRepository } from '../../src/repositories/activity.ts';
import { SqliteFindingsRepository } from '../../src/repositories/findings.ts';
import { SqliteSecretVaultRepository } from '../../src/repositories/secret-vault.ts';
import { SqliteSecurityRepository } from '../../src/repositories/security.ts';
import { corpusConnection, seedCaptureCorpus } from '../helpers/corpus.ts';
import type { PlanStep, RecordedQuery } from '../helpers/query-plans.ts';
import {
  classifyPlanRow,
  explain,
  indexOwners,
  recordingConnection,
} from '../helpers/query-plans.ts';
import type { OwnedTempStore } from '../helpers/temp-store.ts';
import { createTempStore } from '../helpers/temp-store.ts';

const CORPUS_EVENTS = 3_000;
const CORPUS_SESSIONS = 30;

/**
 * The corpus's own clock, not the wall clock.
 *
 * `generate.ts` stamps every event from a fixed 2024 epoch so a windowed read
 * returns the same rows on every machine and every day. The windowed reads
 * default to `Date.now()`, which is years past that — so with the real clock
 * every `WHERE started_at >= :from` matches NOTHING, and the plan captured would
 * be a plan for an empty window. It would still be a real plan, which is what
 * makes this the quiet kind of mistake: the assertions pass and describe a query
 * the dashboard never issues against data.
 *
 * Taken from the corpus the generator reports having written (`endsAt`), never
 * recomputed from a copy of its epoch: a hand-rolled copy is what goes stale
 * without a compile error, and this is the value it would go stale into. It
 * rides on `Surfaces` so every read below reaches it the same way.
 */
const DAY_MS = 86_400_000;

/**
 * Every read the dashboard's four store-heavy pages issue, in page order.
 *
 * `/security` is the eight-way `Promise.all` the budget names. `/activity` and
 * `/vault` are here because they read the same growing tables and are budgeted
 * alongside it. A page that grows a read and does not add it here is the gap
 * this list can't close on its own — which is why the count is asserted below.
 */
interface HotRead {
  readonly name: string;
  readonly run: (ctx: Surfaces) => unknown;
}

interface Surfaces {
  readonly security: SqliteSecurityRepository;
  readonly findings: SqliteFindingsRepository;
  readonly activity: SqliteActivityRepository;
  readonly vault: SqliteSecretVaultRepository;
  readonly sessionId: string;
  /** The corpus's own end instant — see the note above. */
  readonly now: number;
  /** A cursor into the flat list, so the keyset page read is driven with a real one. */
  readonly secondPageCursor: string;
}

const HOT_READS: readonly HotRead[] = [
  // --- /security: the eight aggregations of one Promise.all -----------------
  { name: '/security severitySummary', run: (c) => c.security.severitySummary() },
  { name: '/security enforcementActions', run: (c) => c.security.enforcementActions('30d') },
  { name: '/security findingsTimeseries', run: (c) => c.security.findingsTimeseries('30d') },
  { name: '/security mttrTrend', run: (c) => c.security.mttrTrend('30d') },
  { name: '/security scanCoverage', run: (c) => c.security.scanCoverage('30d') },
  { name: '/security topSources', run: (c) => c.security.topSources('30d', { limit: 5 }) },
  { name: '/security recentlyResolved', run: (c) => c.security.recentlyResolved() },
  { name: '/security recentFindings', run: (c) => c.findings.recentFindings({ limit: 500 }) },
  // --- /findings: three views over one filtered set ---------------------------
  // Each view is its own read, and the session-scoped grouped read is listed
  // separately because the scope changes which index drives the scan.
  { name: '/findings listGroupedFindings', run: (c) => c.findings.listGroupedFindings({}) },
  {
    name: '/findings listGroupedFindings (session)',
    run: (c) => c.findings.listGroupedFindings({ sessionId: c.sessionId }),
  },
  { name: '/findings listFindingInstances', run: (c) => c.findings.listFindingInstances({}) },
  {
    name: '/findings listFindingInstances (page 2)',
    run: (c) => c.findings.listFindingInstances({ cursor: c.secondPageCursor }),
  },
  {
    name: '/findings listFindingInstances (session)',
    run: (c) => c.findings.listFindingInstances({ sessionId: c.sessionId }),
  },
  { name: '/findings listFindingLocations', run: (c) => c.findings.listFindingLocations({}) },
  {
    name: '/findings listFindingLocations (session)',
    run: (c) => c.findings.listFindingLocations({ sessionId: c.sessionId }),
  },
  // --- /activity -------------------------------------------------------------
  { name: '/activity stats', run: (c) => c.activity.stats() },
  {
    name: '/activity listSessions',
    run: (c) =>
      c.activity.listSessions({
        excludeEmpty: true,
        from: new Date(c.now - 30 * DAY_MS).toISOString(),
        limit: 100,
      }),
  },
  { name: '/activity tokenReports', run: (c) => c.activity.tokenReports(c.now - 30 * DAY_MS) },
  {
    name: '/activity harnessFacets',
    run: (c) => c.activity.harnessFacets(c.now - 30 * DAY_MS),
  },
  { name: '/activity getSession', run: (c) => c.activity.getSession(c.sessionId) },
  {
    name: '/activity tokenReportForSession',
    run: (c) => c.activity.tokenReportForSession(c.sessionId),
  },
  {
    name: '/activity sessionFindingsCount',
    run: (c) => c.findings.sessionFindingsCount(c.sessionId),
  },
  // --- /vault ----------------------------------------------------------------
  { name: '/vault listInventory', run: (c) => c.vault.listInventory({}, c.now) },
  { name: '/vault listReuse', run: (c) => c.vault.listReuse({}, c.now) },
  { name: '/vault listDerefs', run: (c) => c.vault.listDerefs({}) },
];

/**
 * The full-index scans that exist today: `read → the tables it walks entirely`.
 *
 * Each is O(rows) and therefore a place the dashboard slows down as the store
 * fills. None is a bug; all three groups have a reason:
 *
 *  - `finding_resolution` — the latest-resolution-wins derived table
 *    (`resolution-sql.ts`) ranks EVERY resolution row before the outer query
 *    filters it, so the three reads sharing that fragment all walk the whole
 *    index. It is the shared cost of that fragment, not of any one read.
 *  - `secret_vault` — the inventory and reuse listings are ordered, paginated
 *    reads of the whole vault plus a `COUNT(*)` over it, which is what a "list
 *    everything" surface is.
 *  - `secret_vault_deref` — the dereference feed, likewise.
 *
 * Empty means "this read walks nothing in full", which is the state to aim for.
 */
const EXPECTED_FULL_INDEX_SCANS: Readonly<Record<string, readonly string[]>> = {
  '/security severitySummary': ['finding_resolution'],
  '/security enforcementActions': [],
  '/security findingsTimeseries': [],
  '/security mttrTrend': ['finding_resolution'],
  '/security scanCoverage': [],
  '/security topSources': [],
  '/security recentlyResolved': ['finding_resolution'],
  // The ONE entry in this set that does not grow with the store, and the reason
  // the paragraph above says "usually" rather than "always". `recentFindings`
  // scans `idx_audit_started_at` in DESC order precisely so its `LIMIT` can stop
  // the scan after `limit` findings — EXPLAIN QUERY PLAN has no way to say
  // "terminates early", so a bounded scan and an unbounded one print the same
  // word. Measured at 0.9 ms against 35.0 ms for the temp-B-tree form it
  // replaced, on the same 40,000-event store.
  //
  // So this row must not be read as a cost to remove: removing it means going
  // back to sorting every finding in the store. What DOES bound it is a ratio
  // across two store sizes, which a plan cannot express and
  // `security-page-scale.test.ts` asserts instead.
  '/security recentFindings': ['audit_events'],
  // The findings page. Every unscoped read here walks `idx_audit_started_at`
  // in DESC order the way `recentFindings` does, and for the same reason: the
  // order the page wants falls out of the index, so nothing is sorted. Two of
  // the three are UNBOUNDED by design — the flat list and the locations fold
  // count and facet every finding in scope, so the scan is the answer — and
  // the ratio in `findings-page-scale.test.ts` is what states that they are
  // flat in the STORE once a scope narrows them. The grouped read's scan
  // stops early too, but NOT on a fixed row count the way `recentFindings`'
  // LIMIT does: it stops once every rule has its preview cap, and that sum
  // (`rules * PREVIEW_INSTANCES_PER_GROUP`) grows with the rule count, so a
  // plan cannot show the bound and neither can this comment overstate it as
  // constant — see `previewRows`' docblock in findings.ts for the real one.
  // Its `finding_resolution` entry is the latest-resolution derived table the
  // aggregate joins, shared with the three `/security` reads above. The
  // session-scoped grouped read drives from `idx_audit_session` instead, so
  // only that derived table remains.
  '/findings listGroupedFindings': ['audit_events', 'finding_resolution'],
  '/findings listGroupedFindings (session)': ['finding_resolution'],
  '/findings listFindingInstances': ['audit_events'],
  // ONE statement, the same one page 1 runs: the page-2 items are collected
  // inline once the scan passes the cursor (listFindingInstances'
  // isPastCursor), not a second, narrower statement.
  '/findings listFindingInstances (page 2)': ['audit_events'],
  // Session-scoped, so `idx_audit_session` drives it the way the grouped
  // read's session variant is driven — and unlike that variant, the flat
  // and locations reads answer their resolution status through the
  // CORRELATED form (one backward `idx_finding_resolution_key_created` probe
  // per row), never the derived table, so neither one full-scans it even
  // unscoped. Empty is the correct answer here, not an oversight.
  '/findings listFindingInstances (session)': [],
  '/findings listFindingLocations': ['audit_events'],
  '/findings listFindingLocations (session)': [],
  '/activity stats': [],
  '/activity listSessions': [],
  '/activity tokenReports': [],
  '/activity harnessFacets': [],
  '/activity getSession': [],
  '/activity tokenReportForSession': [],
  '/activity sessionFindingsCount': [],
  '/vault listInventory': ['secret_vault', 'secret_vault'],
  '/vault listReuse': ['secret_vault', 'secret_vault'],
  '/vault listDerefs': ['secret_vault_deref'],
};

describe('query plans of every hot dashboard read', () => {
  // One store for the whole file, not one per test: the corpus is the expensive
  // part and every case reads the same captured plans. `useTempStore` is the
  // per-test shape and would rebuild it three times over.
  let store: OwnedTempStore;
  let plans: Map<string, PlanStep[]>;

  beforeAll(async () => {
    store = createTempStore('aka-query-plans-');
    const db = store.open();
    const corpus = seedCaptureCorpus(db, {
      events: CORPUS_EVENTS,
      sessions: CORPUS_SESSIONS,
      seed: 1,
    });

    const raw = corpusConnection(db);
    const owners = indexOwners(raw);

    const sessionRow = raw
      .prepare(
        `SELECT root_session_id AS id FROM audit_events WHERE root_session_id IS NOT NULL LIMIT 1`,
      )
      .get() as { id: string } | undefined;
    // The fan-out reads only prepare their statements once a session resolves,
    // so a missing id would quietly shrink the surface under test rather than
    // fail it.
    expect(
      sessionRow?.id,
      'corpus produced no session to drive the /activity detail reads',
    ).toBeTypeOf('string');

    // A real cursor off a real first page, taken through the RAW handle so the
    // read that mints it is not itself recorded. A hand-rolled cursor could
    // decode to null, and a null cursor silently degrades to the first page —
    // a plan for a read the case does not claim to cover.
    const firstPage = await new SqliteFindingsRepository(raw).listFindingInstances({});
    expect(
      firstPage.nextCursor,
      'corpus produced fewer findings than one flat page, so the keyset read has no page to seek',
    ).toBeTypeOf('string');

    const recorded: RecordedQuery[] = [];
    const spy = recordingConnection(raw, recorded);
    const surfaces: Surfaces = {
      security: new SqliteSecurityRepository(spy, () => corpus.endsAt),
      findings: new SqliteFindingsRepository(spy),
      activity: new SqliteActivityRepository(spy),
      vault: new SqliteSecretVaultRepository(spy),
      sessionId: sessionRow?.id ?? '',
      now: corpus.endsAt,
      secondPageCursor: firstPage.nextCursor ?? '',
    };

    plans = new Map();
    for (const read of HOT_READS) {
      recorded.length = 0;
      read.run(surfaces);
      // EXPLAIN goes through the RAW handle, so the recorder does not capture
      // its own explains and recurse.
      plans.set(
        read.name,
        recorded.flatMap((q) => explain(raw, q).map((row) => classifyPlanRow(row.detail, owners))),
      );
    }
  });

  afterAll(() => {
    store.destroy();
  });

  it('drives every hot read, and each one issues at least one statement', () => {
    // `scanCoverage` is the sole exception and is named rather than skipped: it
    // returns a curated constant and touches no store at all. Without this
    // check a read whose repository stopped issuing SQL would contribute an
    // empty plan list, satisfy every assertion below vacuously, and look
    // exactly like a read that had been optimised.
    expect(plans.size).toBe(HOT_READS.length);
    for (const [name, steps] of plans) {
      if (name === '/security scanCoverage') {
        expect(steps, 'scanCoverage reads no table; it returns a constant').toEqual([]);
        continue;
      }
      expect(steps.length, `${name} issued no SQL`).toBeGreaterThan(0);
    }
  });

  it('no hot read scans a table with no index', () => {
    const offenders = [...plans].flatMap(([name, steps]) =>
      steps.filter((s) => s.kind === 'full-table').map((s) => `${name}: ${s.detail}`),
    );
    expect(offenders).toEqual([]);
  });

  it('the full-index scans are exactly the ones written down', () => {
    const actual = Object.fromEntries(
      [...plans].map(([name, steps]) => [
        name,
        steps
          .filter((s) => s.kind === 'full-index')
          .map((s) => s.table ?? '<unresolved>')
          .sort(),
      ]),
    );
    const expected = Object.fromEntries(
      Object.entries(EXPECTED_FULL_INDEX_SCANS).map(([name, tables]) => [name, [...tables].sort()]),
    );
    expect(actual).toEqual(expected);
  });
});
