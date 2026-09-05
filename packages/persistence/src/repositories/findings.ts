import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import type {
  ActionTaken,
  DayActivity,
  FindingGroupAggregate,
  FindingInstanceDetail,
  FindingLocationFile,
  FindingStatus,
  FindingTypeSummary,
  FindingView,
  FlatFindingRow,
  HealthSummary,
  InstanceFilterOptions,
  ListFindingInstancesQuery,
  ListFindingInstancesResponse,
  ListFindingLocationsQuery,
  ListFindingLocationsResponse,
  ListFindingTypesQuery,
  ListFindingTypesResponse,
  LocationAccumulator,
} from '@akasecurity/schema';
import {
  ACTION_TAKEN_KEYS,
  addToLocation,
  applyFindingFilters,
  buildFindingTypes,
  CAPTURE_EVENT_TYPES_SQL,
  compareFindingGroupOrder,
  computeFindingFacets,
  countInstancesByStatus,
  createInstanceFacetAccumulator,
  DEFAULT_FINDING_TYPES_LIMIT,
  DEFAULT_FLAT_FINDINGS_LIMIT,
  deriveFindingStatus,
  ENFORCEABLE_CATEGORIES,
  epochMillisToIso,
  foldGroupStatus,
  isoToEpochMillis,
  matchesInstanceFilters,
  newLocationAccumulator,
  sortFindingTypes,
  toInstanceDetail,
} from '@akasecurity/schema';

import { parseJsonObject } from '../internal/json.ts';
import { decodeKeysetCursor, encodeKeysetCursor } from '../internal/keyset-cursor.ts';
import { allRows, countBy, countScalar, iterateRows } from '../internal/rows.ts';
import type {
  DashboardViews,
  FindingInstancesView,
  FindingsReadPort,
  FindingTypesView,
} from '../ports.ts';
import { LATEST_RESOLUTION_BY_KEY_SQL, latestResolutionStatusSql } from './resolution-sql.ts';

// Repos returned by listFindingLocations when the query names no limit.
const DEFAULT_LOCATIONS_LIMIT = 100;

// Distinct rules named on one location row. The row renders them as chips and
// the instance count is what conveys scale, so the list is a sample, not a tally.
const LOCATION_RULE_IDS_CAP = 20;

/** Location rows sort like groups: worst severity first, then most recent. */
function compareLocationOrder(
  a: { maxSeverity: string; latestDetectedAt: string },
  b: { maxSeverity: string; latestDetectedAt: string },
): number {
  return compareFindingGroupOrder(
    {
      severity: a.maxSeverity as FindingTypeSummary['severity'],
      latestDetectedAt: a.latestDetectedAt,
      id: '',
    },
    {
      severity: b.maxSeverity as FindingTypeSummary['severity'],
      latestDetectedAt: b.latestDetectedAt,
      id: '',
    },
  );
}

// group_concat's list separator. SQLite allows a custom separator only when the
// aggregate has a single argument, and DISTINCT already claims that slot, so the
// default ',' is what the aggregate queries below emit.
const CONCAT_SEP = ',';
// Separates the fields of one encoded deriveFindingStatus input tuple (and its
// trailing instance count). Both this and CONCAT_SEP are absent from the enum
// values being encoded (event.kind, finding_resolution.status) and from the
// count digits.
const TUPLE_SEP = '|';

function splitConcat(value: string | null): string[] {
  return value === null || value === '' ? [] : value.split(CONCAT_SEP);
}

// One groupAggregates() row: the whole-group folds for a single rule_id. The
// group_concat columns are null when the group has no non-null value for that
// column (e.g. audit_events whose attributes carry no repo).
interface FindingAggregateRowJoined {
  rule_id: string;
  severity: string;
  category: string;
  instance_count: number;
  latest_at: number;
  source_tools: string | null;
  actions_taken: string | null;
  status_inputs: string | null;
  repos: string | null;
  files: string | null;
  tool_names: string | null;
}

interface FindingGroupRowJoined {
  id: string;
  rule_id: string;
  category: string;
  severity: string;
  masked_match: string;
  action_taken: string;
  confidence: number;
  occurred_at: number;
  source_tool: string;
  repo: string | null;
  file: string | null;
  tool_name: string | null;
  event_id: string;
  session_id: string | null;
  // Status-derivation inputs — mirrors SqliteSecurityRepository.severitySummary's
  // atRest/latest-resolution-wins predicate (see deriveInstanceStatus below).
  kind: string;
  finding_key: string | null;
  latest_status: string | null;
}

// Per-row FindingStatus — a thin snake_case adapter over @akasecurity/schema's
// deriveFindingStatus, the ONE shared classifier (see its doc for the full
// semantics, including the
// reviewed 'dismissed' asymmetry vs severitySummary's caught bucket). The
// status↔bucket contract is pinned by resolution-consistency.test.ts; when a
// dismiss-writer ships, revisit the shared classifier and severitySummary's
// CASE buckets together.
function deriveInstanceStatus(row: {
  kind: string;
  finding_key: string | null;
  latest_status: string | null;
}): FindingStatus {
  return deriveFindingStatus({
    kind: row.kind,
    findingKey: row.finding_key,
    latestResolutionStatus: row.latest_status,
  });
}

/**
 * `FindingGroupRowJoined` -> `FlatFindingRow`, the one field-by-field mapping
 * every instance-level read needs: `scanFindingRows`' yield, and
 * `findingInstance`'s single seeked row. Kept here rather than duplicated at
 * both call sites so a column `findingScanSql` starts projecting is threaded
 * through once, not twice with the risk of the two drifting — see
 * `scanFindingRows`' generator for what that drift would mean.
 */
function toFlatFindingRow(r: FindingGroupRowJoined): FlatFindingRow {
  return {
    id: r.id,
    ruleId: r.rule_id,
    category: r.category,
    severity: r.severity,
    maskedMatch: r.masked_match,
    actionTaken: r.action_taken,
    confidence: r.confidence,
    occurredAt: epochMillisToIso(r.occurred_at),
    sourceTool: r.source_tool,
    repo: r.repo ?? '',
    file: r.file ?? '',
    ...(r.tool_name === null ? {} : { toolName: r.tool_name }),
    eventId: r.event_id,
    ...(r.session_id === null ? {} : { sessionId: r.session_id }),
    status: deriveInstanceStatus(r),
  };
}

// The grouped list's cursor: the sort key of the last group on the page just
// served. Its own codec rather than the shared keyset one, because this list
// sorts by (severity, latestDetectedAt, id) — not by a timestamp and an id — so
// resuming needs all three. Undecodable restarts from the top, matching the
// convention the other paginated reads follow.
type GroupCursorPayload = Pick<FindingTypeSummary, 'severity' | 'latestDetectedAt' | 'id'>;

function encodeGroupCursor(group: GroupCursorPayload): string {
  const payload = {
    sev: group.severity,
    t: group.latestDetectedAt,
    id: group.id,
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function decodeGroupCursor(cursor: string): GroupCursorPayload | null {
  const parsed = parseJsonObject(Buffer.from(cursor, 'base64url').toString('utf8'));
  if (
    parsed !== undefined &&
    typeof parsed.sev === 'string' &&
    typeof parsed.t === 'string' &&
    typeof parsed.id === 'string'
  ) {
    // `sev` is not checked against the Severity enum: an out-of-enum value ranks
    // below every known severity (see compareFindingGroupOrder), so a garbage
    // cursor sorts before the whole list and degrades to a restart from the top
    // — the same outcome as an undecodable one.
    return {
      severity: parsed.sev as FindingTypeSummary['severity'],
      latestDetectedAt: parsed.t,
      id: parsed.id,
    };
  }
  return null;
}

/** Index of the first group strictly after the cursor, or the length when none. */
function firstAfter(sorted: FindingTypeSummary[], cursor: GroupCursorPayload): number {
  const index = sorted.findIndex((t) => compareFindingGroupOrder(t, cursor) > 0);
  return index === -1 ? sorted.length : index;
}

/**
 * The group a `?finding=` deep link names, when it is not already on the page:
 * either the group itself, or the group holding the named instance. Returns
 * undefined when the id is unknown or already present.
 */
function findDeepLinked(
  sorted: FindingTypeSummary[],
  page: FindingTypeSummary[],
  id: string,
): FindingTypeSummary | undefined {
  if (page.some((t) => t.id === id)) return undefined;
  return sorted.find((t) => t.id === id);
}

/**
 * The projected columns every instance-level read shares — the SELECT list
 * alone, without a FROM.
 *
 * Only the columns are shared, deliberately. The two readers need OPPOSITE join
 * orders: the scan drives from `audit_events` in index order (its CROSS JOINs
 * pin that, so the page order falls out of the index), while the single-row
 * seek must drive from `inspection_findings` off its primary key. Sharing the
 * FROM as well put `audit_events` on the outside of the seek too and turned a
 * primary-key lookup into a full scan of the table — caught by
 * `hot-read-query-plans.test.ts`, which is why it is a comment here and not a
 * defect in the tree. `toFlatFindingRow` maps these once, so a column added
 * here still reaches both readers or neither.
 */
const FINDING_ROW_COLUMNS_SQL = `f.id AS id, d.rule_id AS rule_id, d.category AS category,
              d.severity AS severity, f.masked_match AS masked_match,
              f.action_taken AS action_taken, f.confidence AS confidence,
              e.started_at AS occurred_at,
              e.source_tool AS source_tool,
              e.repo AS repo,
              e.file_path AS file,
              e.tool_name AS tool_name,
              f.audit_event_id AS event_id, e.root_session_id AS session_id,
              e.event_type AS kind, f.finding_key AS finding_key,
              ${latestResolutionStatusSql('f')} AS latest_status`;

const DAY_MS = 86_400_000;

interface FindingRowJoined {
  id: string;
  event_id: string;
  rule_id: string;
  category: string;
  severity: string;
  masked_match: string;
  action_taken: string;
  confidence: number;
  occurred_at: number;
  source_tool: string;
  kind: string;
}

/**
 * Findings read surfaces (/findings, /health, /audit) over the generalized
 * `inspection_findings`⋈`audit_events`⋈`inspection_definitions` join, bound to
 * one open DB. The legacy `findings` table this class once wrote directly no
 * longer exists (recordCapture writes `inspection_findings` via
 * SqliteInspectionFindingsRepository instead — see database.ts); a dropped-
 * then-viewed compatibility shape backs any already-shipped binary that still
 * writes the old table by name. Every query reads the whole store — no row carries an owner column to scope by.
 */
export class SqliteFindingsRepository
  implements FindingsReadPort, DashboardViews, FindingTypesView, FindingInstancesView
{
  constructor(private readonly db: DatabaseSync) {}

  /**
   * The newest `limit` findings, newest first.
   *
   * THE PLAN IS THE POINT HERE, and two things in the SQL below exist only to
   * pin it. The natural spelling — drive from `inspection_findings`, order by the
   * JOINED `e.started_at` — cannot push the LIMIT down, because the sort key is
   * not on the driving table: SQLite sorts every finding in the store through a
   * temp B-tree to return 500 rows. Measured at 35.0 ms on a 40,000-event corpus
   * against 0.9 ms for the form below, and the gap is a ratio of the store size
   * rather than a constant.
   *
   * What it takes to make `started_at` order come out of an index instead:
   *
   *  - **`+e.event_type`** — the unary plus makes that term non-indexable, so the
   *    planner stops choosing `idx_audit_type_t` (`event_type, started_at`). That
   *    index cannot serve the ORDER BY: the predicate spans four event types, so
   *    satisfying a global `started_at` order across them needs a range merge
   *    SQLite will not do, and it sorts instead. Freed of it, the planner scans
   *    `idx_audit_started_at` — a bare `started_at` index — in DESC order and
   *    filters the type per row, which lets the LIMIT stop the scan early.
   *  - **`CROSS JOIN`** — semantically identical to JOIN in SQLite, and there
   *    purely to stop the tables being reordered. With plain JOINs the planner
   *    drives from `f` and sorts everything again: measured at 23.6 ms, i.e. the
   *    unary plus ALONE recovers almost none of the win. Both are needed.
   *
   * Neither is a micro-optimisation that a later reader should tidy away, and
   * `packages/persistence/test/performance/hot-read-query-plans.test.ts` fails if
   * the temp B-tree comes back.
   *
   * Degrading gracefully was the reason for `+` over `INDEXED BY`, which measured
   * identically (0.9 ms): `INDEXED BY` is a hard requirement, so dropping or
   * renaming the index turns this read into an ERROR, where `+` turns it into a
   * scan-and-sort — slower, still correct. The worst case for the chosen form is
   * a store whose recent captures carry no findings at all, where the scan walks
   * the whole index; that is still no worse than the full sort it replaced.
   */
  recentFindings(opts?: { limit?: number }): Promise<FindingView[]> {
    const limit = opts?.limit ?? 50;
    const rows = allRows<FindingRowJoined>(
      this.db.prepare(
        `SELECT f.id, f.audit_event_id AS event_id, d.rule_id, d.category, d.severity,
                f.masked_match, f.action_taken, f.confidence, e.started_at AS occurred_at,
                e.source_tool AS source_tool,
                e.event_type AS kind
         FROM audit_events e
         CROSS JOIN inspection_findings f ON f.audit_event_id = e.id
         CROSS JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         WHERE +e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
         ORDER BY e.started_at DESC, f.rowid DESC
         LIMIT :limit`,
      ),
      { limit },
    );
    return Promise.resolve(
      rows.map((r) => ({
        id: r.id,
        eventId: r.event_id,
        ruleId: r.rule_id,
        category: r.category,
        severity: r.severity,
        maskedMatch: r.masked_match,
        actionTaken: r.action_taken as ActionTaken,
        confidence: r.confidence,
        occurredAt: epochMillisToIso(r.occurred_at),
        sourceTool: r.source_tool,
        kind: r.kind,
      })),
    );
  }

  /** Live-enforced findings recorded for one session — a bare COUNT over the
   * session-stamped audit_events (served by idx_audit_session), so the Activity
   * page can label its findings link without the grouped pipeline. */
  sessionFindingsCount(sessionId: string): Promise<number> {
    if (!sessionId) return Promise.resolve(0);
    return Promise.resolve(
      countScalar(
        this.db,
        `SELECT count(*) AS n FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
          WHERE e.root_session_id = :sessionId
            AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})`,
        { sessionId },
      ),
    );
  }

  /** Per-rule transcript firing tally for one session — every detection the
   * transcript-reconciler pass recorded against the session's `tool_call` rows,
   * counted per firing rather than per unique value. Rides on session-scoped
   * grouped responses so the findings view can reconcile the Activity page's
   * tally with the deduped groups it lists.
   *
   * `inspection_findings`/`audit_events` are now the SAME physical tables the
   * rest of this class reads for the live-capture list above (they used to be
   * a separate store), so this excludes the four capture kinds those rows
   * already carry — without that exclusion, every live-capture finding in the
   * session would be tallied here too, double-counting against the grouped
   * list this response rides alongside. The reconciler attaches its findings
   * only to `tool_call` rows, which the exclusion leaves untouched. */
  private sessionFirings(sessionId: string): Record<string, number> {
    return Object.fromEntries(
      countBy(
        this.db,
        `SELECT d.rule_id AS k, count(*) AS n
           FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id
          WHERE e.root_session_id = :sessionId
            AND e.event_type NOT IN (${CAPTURE_EVENT_TYPES_SQL})
          GROUP BY d.rule_id`,
        { sessionId },
      ),
    );
  }

  /**
   * Finding TYPES for the dashboard — one row per rule, scoped to the four
   * capture kinds (audit_events also holds structural/reconciler/scan rows this
   * list must never surface), with per-filter-excluded facets, the requested
   * filters applied, and sorted by severity then recency. Filtering and faceting
   * run in JS via the shared @akasecurity/schema helpers. `totals` reflect the
   * full filtered set; `items` is the requested page (default 50), keyset-paged.
   * Under a `status` filter, `totals.findings` counts only findings whose
   * derived status was requested.
   *
   * ONE read, which materializes no findings: a single aggregate per rule_id,
   * folding EVERY finding into the numbers a type row and the filters need
   * (count, severity, category, providers, actions, statuses, latest, search
   * text). The findings OF a type come from listFindingInstances scoped to
   * `subtype`, so neither list bounds the other and no per-type cap exists.
   *
   * The aggregates carry raw DB values and are translated by the same
   * @akasecurity/schema mappers every other path uses, so no enum mapping or
   * status rule is ever restated in SQL.
   */
  listFindingTypes(query: ListFindingTypesQuery): Promise<ListFindingTypesResponse> {
    // The session scope is a SQL predicate, not a JS filter: totals, facets and
    // the per-type aggregates must all speak for the session only, and the
    // aggregate query never materializes a row per finding to filter in JS.
    // The capture-kind constraint is unconditional (see CAPTURE_EVENT_TYPES_SQL)
    // — audit_events carries structural/reconciler/scan rows this list must
    // never surface, the same universe the old `events` table was already
    // limited to.
    const sessionPredicate = query.sessionId ? ` AND e.root_session_id = :sessionId` : '';
    // The time bound is a SQL predicate for the same reason: totals, facets and
    // aggregates must all speak for the window.
    const fromMs = query.from === undefined ? undefined : isoToEpochMillis(query.from);
    const fromPredicate = fromMs === undefined ? '' : ` AND e.started_at >= :fromMs`;
    const predicate = `WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})${sessionPredicate}${fromPredicate}`;
    const sessionParams: Record<string, string | number> = {
      ...(query.sessionId ? { sessionId: query.sessionId } : {}),
      ...(fromMs === undefined ? {} : { fromMs }),
    };

    // The ONE read. Every value a type row carries is folded here, in SQL —
    // there is no second pass materializing findings, which is what keeps this
    // bounded by the number of distinct rules rather than by the store.
    //
    // The search text is the one aggregate column whose size tracks the store
    // rather than the rule count, so fetch it only for a request that can use
    // it (see groupAggregates).
    const aggregates = this.groupAggregates(query.q !== undefined && query.q !== '', {
      predicate,
      params: sessionParams,
    });

    // No pack names in OSS: detection.name is null, policy is synthesized from
    // category (both unused by the OSS views).
    const allTypes = buildFindingTypes(aggregates);

    const filterOpts = {
      severity: query.severity,
      providers: query.provider,
      actions: query.action,
      statuses: query.status,
      subtype: query.subtype,
      q: query.q,
    };

    // Facets are per-filter-excluded, so compute them over the unfiltered types.
    const facets = computeFindingFacets(allTypes, filterOpts);
    const sorted = sortFindingTypes(applyFindingFilters(allTypes, filterOpts));

    // Under a status filter, `findings` counts only the instances whose DERIVED
    // status was requested — a type folds to 'open' on the strength of a few
    // open findings, and counting its whole tally would report findings the
    // filter excluded. The per-status counts come from the aggregate's
    // statusInputs; the whole-type instanceCount is the unfiltered total.
    const statusFilter = query.status ?? [];
    const totals = {
      findings: sorted.reduce((acc, t) => {
        if (statusFilter.length === 0) return acc + t.instanceCount;
        const agg = aggregates.get(t.id);
        return (
          acc +
          (agg
            ? (countInstancesByStatus(agg.statusInputs, statusFilter) ?? t.instanceCount)
            : t.instanceCount)
        );
      }, 0),
      types: sorted.length,
    };

    const limit = query.limit ?? DEFAULT_FINDING_TYPES_LIMIT;

    // Page the sorted types by keyset rather than offset. Both are equally
    // cheap here — the whole filtered set is already sorted in memory — but the
    // store is written by processes this read does not coordinate with, and an
    // offset skips or repeats a row whenever a write reorders one between
    // pages. compareFindingGroupOrder is a total order, so "strictly after the
    // cursor" always names exactly one position.
    const cursor = query.cursor === undefined ? null : decodeGroupCursor(query.cursor);
    const start = cursor === null ? 0 : firstAfter(sorted, cursor);
    const page = sorted.slice(start, start + limit);
    // From the page, BEFORE any deep-link append: the appended row is out of
    // sort order, and minting the cursor from it would skip everything between
    // the real page end and wherever it sorts.
    const lastOnPage = page.at(-1);
    const nextCursor =
      start + limit < sorted.length && lastOnPage ? encodeGroupCursor(lastOnPage) : null;

    // Keep the selected type visible once the list pages: it may sort past the
    // page the cursor landed on, and scanning forward for it would be unbounded
    // work for what is often a stale id. Appended out of order, and never
    // counted in totals or the cursor. Names a RULE only — an instance id is
    // resolved by findingInstance, a primary-key seek that no page bounds.
    const deepLinked =
      query.includeId === undefined || query.includeId === ''
        ? undefined
        : findDeepLinked(sorted, page, query.includeId);

    const items = [...page, ...(deepLinked ? [deepLinked] : [])];

    return Promise.resolve({
      totals,
      facets,
      items,
      nextCursor,
      ...(query.sessionId ? { sessionFirings: this.sessionFirings(query.sessionId) } : {}),
    });
  }

  /**
   * One row per rule_id, folding EVERY instance of the group into the values
   * buildFindingGroups cannot recover from a preview. Bounded by the number of
   * distinct rule_ids (the installed packs' rules), not by the store's size.
   *
   * A single scan, folded in two levels: the inner SELECT groups by
   * (rule_id, status tuple) so each (kind, has-key, latest-status) combination
   * carries its instance count — countInstancesByStatus needs those counts for
   * status-scoped totals — and the outer SELECT folds the tuples back to one
   * row per rule. The per-instance sets ride back as group_concat lists of RAW
   * DB values — source_tool, action_taken, and the tuples deriveFindingStatus
   * consumes. Aggregating the status INPUTS rather than a status keeps the
   * classifier itself in @akasecurity/schema, where severitySummary's SQL and
   * this query can't drift apart on what 'resolved' means (see
   * resolution-sql.ts). The concat-of-concats can repeat a value across
   * tuples; the schema mappers dedupe, and each set is bounded by an enum, so
   * a group's row stays small however many findings it holds.
   *
   * `withSearchText` is the exception, and the one column here that does NOT
   * stay small: the group's per-tuple-distinct repos/filePaths, whose size
   * tracks how many distinct paths a rule fired across — for a rule hitting
   * mostly-unique paths that is a string proportional to the store (~8MB over
   * 200k distinct paths, and buildHaystack lowercases a second copy). It buys
   * `q` the ability to match an instance outside the preview, which searching
   * the preview alone would silently lose, so it is fetched only when the
   * request actually carries a `q`. (Substring matching is unaffected by a
   * path repeating across tuples.)
   */
  /**
   * The instance-level (flat) findings list: one row per finding, newest first,
   * paged by keyset.
   *
   * SQL owns SCOPE, JS owns every FILTER DIMENSION. The session and the time
   * bound are SQL predicates: nothing counts them, so narrowing the scan by
   * them changes no reported number. Severity, subtype, provider, action,
   * status, tool, repo, file and `q` all stay in JS — each has a facet, and a
   * facet excludes its own filter, so a row the filter rejects still has to be
   * counted. Pushing any of them into SQL would silently empty its own facet.
   * Several could not be expressed there anyway: status comes from the one
   * shared classifier (deriveFindingStatus), and provider 'api' means "a tool
   * none of the mappers names", which no IN-list can say.
   *
   * The scan runs from the top of the scope on every request, not from the
   * cursor: `totals` and `facets` describe the whole filtered scope and must not
   * move as the caller pages. Rows come off ONE statement, iterated rather
   * than materialized (`scanFindingRows`), so memory stays flat while the
   * counting runs — a generator streaming the index order, not a sequence of
   * fetched batches; only the page itself is retained.
   */
  listFindingInstances(query: ListFindingInstancesQuery): Promise<ListFindingInstancesResponse> {
    const opts: InstanceFilterOptions = {
      severity: query.severity,
      subtype: query.subtype,
      providers: query.provider,
      actions: query.action,
      statuses: query.status,
      tools: query.tool,
      repo: query.repo,
      file: query.file,
      q: query.q,
    };
    const limit = query.limit ?? DEFAULT_FLAT_FINDINGS_LIMIT;
    const cursor = query.cursor === undefined ? null : decodeKeysetCursor(query.cursor);

    // Whether `row` is strictly past `cursor` in the same started_at DESC,
    // id DESC order the scan already walks — the same disjunction a keyset
    // predicate would test in SQL (`startedAt <= X AND (startedAt < X OR
    // id < Y)`), evaluated in JS against the one scan below instead of a
    // second, narrower statement. `cursor` is captured non-null in the
    // closure so the null case costs one allocation, not a per-row branch.
    const isPastCursor: (row: FlatFindingRow) => boolean =
      cursor === null
        ? () => true
        : (row) => {
            const rowMs = isoToEpochMillis(row.occurredAt);
            return (
              rowMs <= cursor.startedAtMs && (rowMs < cursor.startedAtMs || row.id < cursor.id)
            );
          };

    const accumulator = createInstanceFacetAccumulator(opts);
    const items: FindingInstanceDetail[] = [];
    let total = 0;
    let last: FlatFindingRow | undefined;
    // Whether the page is full and at least one further row matched — the
    // cursor is minted from the last COLLECTED row, so no matching row between
    // the page's end and the batch's end is ever skipped.
    let hasMore = false;

    // ONE scan regardless of page: totals and facets always describe the
    // whole filtered scope (so paging cannot move them), and that pass
    // already visits every row a page-2+ request would otherwise re-seek for
    // — `isPastCursor` collects the page inline instead of discarding this
    // pass's tail and re-running a second, cursor-bounded scan for it. A
    // store where the cursor sits deep in the scope no longer pays for that
    // tail twice, and there is no second snapshot for a concurrent write to
    // land between.
    for (const row of this.scanFindingRows({
      sessionId: query.sessionId,
      from: query.from,
    })) {
      accumulator.add(row);
      if (!matchesInstanceFilters(row, opts)) continue;
      total += 1;
      if (!isPastCursor(row)) continue;
      if (items.length < limit) {
        items.push(toInstanceDetail(row));
        last = row;
      } else {
        hasMore = true;
      }
    }

    const nextCursor =
      hasMore && last
        ? encodeKeysetCursor({ startedAtMs: isoToEpochMillis(last.occurredAt), id: last.id })
        : null;

    return Promise.resolve({
      totals: { findings: total },
      facets: accumulator.facets(),
      items,
      nextCursor,
    });
  }

  /**
   * The same findings folded by location: repository, then file within it.
   *
   * The grouping keys come from the capturing event's attributes, which is what
   * the local store relates a finding to — there is no finding↔asset row to
   * group by instead. A repo or file the event did not record folds into the
   * empty-string bucket, which the view renders but does not link, since no
   * filter can name it.
   */
  listFindingLocations(query: ListFindingLocationsQuery): Promise<ListFindingLocationsResponse> {
    const opts: InstanceFilterOptions = {
      severity: query.severity,
      subtype: query.subtype,
      providers: query.provider,
      actions: query.action,
      statuses: query.status,
      tools: query.tool,
      q: query.q,
    };
    const limit = query.limit ?? DEFAULT_LOCATIONS_LIMIT;

    // Bounded by distinct (repo, file) pairs rather than by the store's size —
    // the same cardinality the grouped path's search-text aggregate already
    // carries, holding counts instead of paths.
    const byRepo = new Map<string, Map<string, LocationAccumulator>>();
    let total = 0;

    for (const row of this.scanFindingRows({
      sessionId: query.sessionId,
      from: query.from,
    })) {
      if (!matchesInstanceFilters(row, opts)) continue;
      total += 1;
      let files = byRepo.get(row.repo);
      if (files === undefined) {
        files = new Map<string, LocationAccumulator>();
        byRepo.set(row.repo, files);
      }
      let acc = files.get(row.file);
      if (acc === undefined) {
        acc = newLocationAccumulator();
        files.set(row.file, acc);
      }
      addToLocation(acc, row);
    }

    let fileCount = 0;
    const repos = [...byRepo.entries()].map(([repo, files]) => {
      fileCount += files.size;
      const fileRows: FindingLocationFile[] = [...files.entries()]
        .map(([file, acc]) => ({
          file,
          instanceCount: acc.instanceCount,
          maxSeverity: acc.maxSeverity as FindingLocationFile['maxSeverity'],
          latestDetectedAt: acc.latestDetectedAt,
          ...(foldGroupStatus(acc.statuses) === undefined
            ? {}
            : { status: foldGroupStatus(acc.statuses) }),
          ruleIds: [...acc.ruleIds].slice(0, LOCATION_RULE_IDS_CAP),
        }))
        .sort(compareLocationOrder);
      const rollup = fileRows.reduce(
        (a, f) => ({
          instanceCount: a.instanceCount + f.instanceCount,
          maxSeverity: compareLocationOrder(f, a) < 0 ? f.maxSeverity : a.maxSeverity,
          latestDetectedAt:
            f.latestDetectedAt > a.latestDetectedAt ? f.latestDetectedAt : a.latestDetectedAt,
        }),
        {
          instanceCount: 0,
          maxSeverity: fileRows[0]?.maxSeverity ?? 'low',
          latestDetectedAt: '',
        },
      );
      const statuses = fileRows.map((f) => f.status);
      const folded = foldGroupStatus(statuses);
      return {
        repo,
        instanceCount: rollup.instanceCount,
        maxSeverity: rollup.maxSeverity,
        latestDetectedAt: rollup.latestDetectedAt,
        ...(folded === undefined ? {} : { status: folded }),
        files: fileRows,
      };
    });
    repos.sort(compareLocationOrder);

    return Promise.resolve({
      totals: { findings: total, repos: repos.length, files: fileCount },
      items: repos.slice(0, limit),
      hasMore: repos.length > limit,
    });
  }

  /**
   * Every finding in scope as a FlatFindingRow, newest first, streamed.
   *
   * A generator so a caller streams the scope without it ever being an array:
   * the flat list counts and facets the whole filtered scope, which on a large
   * store is far more rows than any page. The rows come off ONE statement,
   * iterated rather than materialized, in the index order `findingScanSql`
   * arranges — so the scan is a single pass with a block sort of the id
   * tie-break only, never a sort of the scope, where a sequence of
   * keyset-bounded batches re-sorted everything below the cursor on every
   * batch and cost the square of the scope.
   *
   * `sessionId` and `from` carry ONLY what no facet counts — a filter
   * dimension narrowed here would be missing from its own facet, which is
   * computed by excluding that dimension (see listFindingInstances). There is
   * no `after`/cursor parameter: a keyset page is collected inline from this
   * same pass (`listFindingInstances`' `isPastCursor`) rather than by a second,
   * narrower statement, since the counting pass already visits every row a
   * page-2+ request would otherwise re-seek for.
   */
  private *scanFindingRows(scope: {
    sessionId?: string | undefined;
    from?: string | undefined;
  }): Generator<FlatFindingRow> {
    const { sql, params } = this.findingScanSql(scope);
    for (const r of iterateRows<FindingGroupRowJoined>(this.db.prepare(sql), params)) {
      yield toFlatFindingRow(r);
    }
  }

  /**
   * The one statement both instance-level scans run: every finding in scope,
   * joined to its event and definition, newest first.
   *
   * THE PLAN IS THE POINT, and two things in the SQL exist only to pin it —
   * the same two `recentFindings` documents at length, for the same reason:
   *
   *  - **`+e.event_type`** makes the capture-kind predicate non-indexable, so
   *    the planner cannot pick `idx_audit_type_t` and then sort. That index
   *    yields `started_at` order per event type, not across the four, so
   *    satisfying the ORDER BY from it would need a merge SQLite does not do.
   *    Freed of it, the planner walks `idx_audit_started_at` backwards — or
   *    `idx_audit_session` for a session scope, which is also `started_at`
   *    ordered within the session — and the order falls out of the index.
   *  - **`CROSS JOIN`** pins `audit_events` as the driving table. With plain
   *    JOINs the planner drives from the findings and sorts everything.
   *
   * The latest-resolution lookup is the CORRELATED form: only `status` is
   * needed, `idx_finding_resolution_key_created` answers it with one backward
   * index probe per keyed row, and a derived table over the whole resolution
   * table would be materialized before the first row streamed.
   */
  /**
   * One finding by its own id, or null when no such row exists.
   *
   * A primary-key seek on `inspection_findings`, so its cost does not grow with
   * the store — and, unlike anything derived from a list page, it resolves a
   * finding of ANY age. That is what the Findings page's one-shot `?finding=`
   * deep link needs: the id it carries may name a finding thousands of rows
   * older than anything a first page holds.
   *
   * Deliberately UNFILTERED — no capture-kind, session or time predicate. It
   * RESOLVES an id; whether that row would survive the list's current filters is
   * a different question, and hiding the target because a filter excludes it is
   * worse than showing it.
   *
   * `groupId` on the result IS the rule id, so this one read answers both "which
   * type should the list select?" and "what does the drawer show?".
   */
  findingInstance(id: string): Promise<FindingInstanceDetail | null> {
    // Plain JOINs, and the order matters: driving from `inspection_findings`
    // makes this a primary-key seek. The scan's CROSS JOINs would pin
    // `audit_events` on the outside and scan the whole table to find one row.
    const row = this.db
      .prepare(
        `SELECT ${FINDING_ROW_COLUMNS_SQL}
           FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id
          WHERE f.id = ?`,
      )
      .get(id) as unknown as FindingGroupRowJoined | undefined;
    return Promise.resolve(row === undefined ? null : toInstanceDetail(toFlatFindingRow(row)));
  }

  private findingScanSql(scope: { sessionId?: string | undefined; from?: string | undefined }): {
    sql: string;
    params: SQLInputValue[];
  } {
    const conditions = [`+e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})`];
    const params: SQLInputValue[] = [];

    if (scope.sessionId !== undefined && scope.sessionId !== '') {
      conditions.push('e.root_session_id = ?');
      params.push(scope.sessionId);
    }
    if (scope.from !== undefined) {
      conditions.push('e.started_at >= ?');
      params.push(isoToEpochMillis(scope.from));
    }

    const sql = `SELECT ${FINDING_ROW_COLUMNS_SQL}
         FROM audit_events e
         CROSS JOIN inspection_findings f ON f.audit_event_id = e.id
         CROSS JOIN inspection_definitions d ON d.id = f.inspection_definition_id
        WHERE ${conditions.join(' AND ')}
        ORDER BY e.started_at DESC, f.id DESC`;
    return { sql, params };
  }

  private groupAggregates(
    withSearchText: boolean,
    scope: { predicate: string; params: Record<string, string | number> },
  ): Map<string, FindingGroupAggregate> {
    // Tool names ride as their display label ("via Bash") to mirror
    // buildHaystack — see its doc for why the bare name is not searched.
    const innerSearchColumns = withSearchText
      ? `, group_concat(DISTINCT e.repo) AS repos,
           group_concat(DISTINCT e.file_path) AS files,
           group_concat(DISTINCT 'via ' || e.tool_name) AS tool_names`
      : `, NULL AS repos, NULL AS files, NULL AS tool_names`;

    const rows = this.db
      .prepare(
        `SELECT rule_id,
                -- BARE columns beside max(latest_at), which is deliberate and
                -- is SQLite's documented behaviour: with a single min()/max()
                -- in an aggregate query, every bare column takes its value from
                -- the row that produced the extremum. So these are the severity
                -- and category of the definition whose finding is NEWEST, which
                -- is what the row-based build they replaced read off its first
                -- (newest-first) row.
                --
                -- min() is WRONG here and was the defect: inspection_definitions
                -- holds one row per rule VERSION (see its writer — a version bump
                -- mints a new row), so a rule whose severity moved between
                -- versions has several, and min() picks the ALPHABETICALLY
                -- smallest — 'low' over 'medium', but 'critical' over 'high'.
                -- That is arbitrary in direction, and it feeds the badge, the
                -- filter, the facet counts and the primary sort key.
                --
                -- Adding a second min()/max() aggregate here would make these
                -- bare columns ambiguous again; keep max(latest_at) the only one.
                severity,
                category,
                sum(tuple_count) AS instance_count,
                max(latest_at) AS latest_at,
                group_concat(source_tools) AS source_tools,
                group_concat(actions_taken) AS actions_taken,
                group_concat(status_tuple || '${TUPLE_SEP}' || tuple_count) AS status_inputs,
                group_concat(repos) AS repos,
                group_concat(files) AS files,
                group_concat(tool_names) AS tool_names
           FROM (
             SELECT d.rule_id AS rule_id,
                    -- Severity and category are columns of the DEFINITION, and
                    -- a rule can have SEVERAL definitions (one per version), so
                    -- these are grouped on below and resolved to the newest
                    -- firing version by the outer query's bare-column select.
                    -- They ride the aggregate because the type build has no rows
                    -- to read them off — see buildFindingTypes.
                    d.severity AS severity,
                    d.category AS category,
                    e.event_type || '${TUPLE_SEP}' ||
                      (CASE WHEN f.finding_key IS NULL THEN '' ELSE 'k' END) || '${TUPLE_SEP}' ||
                      coalesce(latest.status, '') AS status_tuple,
                    count(*) AS tuple_count,
                    max(e.started_at) AS latest_at,
                    group_concat(DISTINCT e.source_tool) AS source_tools,
                    group_concat(DISTINCT f.action_taken) AS actions_taken
                    ${innerSearchColumns}
               FROM inspection_findings f
               JOIN audit_events e ON e.id = f.audit_event_id
               JOIN inspection_definitions d ON d.id = f.inspection_definition_id
               LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
                 ON latest.finding_key = f.finding_key
              ${scope.predicate}
              GROUP BY d.rule_id, d.severity, d.category, status_tuple
           )
          GROUP BY rule_id`,
      )
      .all(scope.params) as unknown as FindingAggregateRowJoined[];

    return new Map(
      rows.map((r) => [
        r.rule_id,
        {
          instanceCount: r.instance_count,
          severity: r.severity,
          category: r.category,
          sourceTools: splitConcat(r.source_tools),
          actionsTaken: splitConcat(r.actions_taken),
          statusInputs: splitConcat(r.status_inputs).map((tuple) => {
            const [kind = '', keyMarker = '', latestStatus = '', count = ''] =
              tuple.split(TUPLE_SEP);
            return {
              // deriveFindingStatus only distinguishes null from non-null here,
              // so the marker stands in for the key itself (never rendered).
              kind,
              findingKey: keyMarker === '' ? null : keyMarker,
              latestResolutionStatus: latestStatus === '' ? null : latestStatus,
              count: Number(count),
            };
          }),
          latestDetectedAt: epochMillisToIso(r.latest_at),
          // Free text only — joined and substring-matched, so group_concat's
          // commas need no unpicking (a repo/path containing one still matches).
          // Left undefined (not '') when unfetched, so buildFindingGroups can
          // tell "no q this request" from "a group with no repo/file at all"
          // and skip priming a haystack nothing will read.
          ...(withSearchText
            ? {
                searchText: [r.repos ?? '', r.files ?? '', r.tool_names ?? '']
                  .filter((s) => s !== '')
                  .join(' '),
              }
            : {}),
        },
      ]),
    );
  }

  healthSummary(): Promise<HealthSummary> {
    const total = countScalar(
      this.db,
      `SELECT count(*) AS n FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
        WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})`,
    );
    const byAction = Object.fromEntries(ACTION_TAKEN_KEYS.map((a) => [a, 0])) as Record<
      ActionTaken,
      number
    >;
    const grouped = allRows<{ action_taken: string; c: number }>(
      this.db.prepare(
        `SELECT f.action_taken AS action_taken, count(*) AS c
           FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
          WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
          GROUP BY f.action_taken`,
      ),
    );
    for (const row of grouped) {
      if (row.action_taken in byAction) byAction[row.action_taken as ActionTaken] = row.c;
    }

    // Whole-store OPEN-findings count per severity — powers the read surfaces'
    // status bar so its tally doesn't drift with each command's row limit.
    // Resolution-aware, mirroring SqliteSecurityRepository.severitySummary's
    // latest-resolution-wins convention (see resolution-sql.ts): a finding
    // whose finding_key's NEWEST finding_resolution row is 'resolved' has been
    // remediated and drops out of the tally, while any other latest status
    // (none, or a redetected 'open') keeps counting. Only 'resolved' clears a
    // finding — a future 'acknowledged' disposition is accepted risk, not a
    // fix. In-flight/legacy rows carry finding_key NULL, never join a
    // resolution row, and so always count.
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const sevRows = allRows<{ severity: string; c: number }>(
      this.db.prepare(
        `SELECT d.severity AS severity, count(*) AS c
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
           ON latest.finding_key = f.finding_key
         WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
           AND (latest.status IS NULL OR latest.status != 'resolved')
         GROUP BY d.severity`,
      ),
    );
    for (const row of sevRows) {
      if (row.severity in bySeverity) bySeverity[row.severity as keyof typeof bySeverity] = row.c;
    }

    // Coverage counts ENFORCEABLE categories only: observe-only categories
    // ('config') sit outside the live-capture enforcement path, so their seeded
    // policy would otherwise inflate the numerator against a shrunken
    // denominator (or drag every store's % down if counted in both).
    const categories = ENFORCEABLE_CATEGORIES;
    const enabledRows = allRows<{ category: string }>(
      this.db.prepare(
        `SELECT DISTINCT json_extract(target, '$.category') AS category
         FROM policies WHERE enabled = 1 AND json_extract(target, '$.category') IS NOT NULL`,
      ),
    );
    const enabled = new Set(enabledRows.map((r) => r.category));
    const coverage =
      categories.length === 0
        ? 0
        : categories.filter((c) => enabled.has(c)).length / categories.length;

    return Promise.resolve({ findings: total, byAction, bySeverity, coverage });
  }

  activityByDay(days = 7): Promise<DayActivity[]> {
    const since = startOfUtcDay(Date.now()) - (days - 1) * DAY_MS;
    const rows = allRows<{
      day: string;
      action: string;
      c: number;
    }>(
      this.db.prepare(
        `SELECT date(e.started_at / 1000, 'unixepoch') AS day, f.action_taken AS action, count(*) AS c
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         WHERE e.started_at >= :since
           AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
         GROUP BY day, f.action_taken`,
      ),
      { since },
    );

    // Pre-fill every day in the window so the read surface can draw a continuous
    // bar chart even on days with no activity.
    const buckets = new Map<string, DayActivity>();
    for (let i = 0; i < days; i++) {
      const day = isoDay(since + i * DAY_MS);
      buckets.set(day, { day, total: 0, redacted: 0, warned: 0, blocked: 0 });
    }
    for (const row of rows) {
      const bucket = buckets.get(row.day);
      if (!bucket) continue;
      bucket.total += row.c;
      if (row.action === 'redact') bucket.redacted += row.c;
      else if (row.action === 'warn') bucket.warned += row.c;
      else if (row.action === 'block') bucket.blocked += row.c;
    }
    return Promise.resolve([...buckets.values()].sort((a, b) => a.day.localeCompare(b.day)));
  }
}

function startOfUtcDay(ms: number): number {
  return Math.floor(ms / DAY_MS) * DAY_MS;
}

function isoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
