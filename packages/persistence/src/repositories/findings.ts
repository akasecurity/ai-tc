import type { DatabaseSync } from 'node:sqlite';

import type {
  ActionTaken,
  DayActivity,
  FindingGroupAggregate,
  FindingStatus,
  FindingView,
  GroupableFindingRow,
  HealthSummary,
  ListGroupedFindingsQuery,
  ListGroupedFindingsResponse,
} from '@akasecurity/schema';
import {
  ACTION_TAKEN_KEYS,
  applyFindingFilters,
  buildFindingGroups,
  computeFindingFacets,
  countInstancesByStatus,
  DEFAULT_GROUPED_FINDINGS_LIMIT,
  deriveFindingStatus,
  ENFORCEABLE_CATEGORIES,
  epochMillisToIso,
  sortFindingGroups,
} from '@akasecurity/schema';

import { allRows, countBy, countScalar } from '../internal/rows.ts';
import type { DashboardViews, FindingsReadPort, GroupedFindingsView } from '../ports.ts';
import { LATEST_RESOLUTION_BY_KEY_SQL } from './resolution-sql.ts';

// How many of each group's newest instances listGroupedFindings materializes.
// Group-wide numbers (instanceCount, providers, actions, status, latest, search
// text) are aggregated SQL-side over EVERY instance and handed to
// buildFindingGroups, so this bounds only the per-group `instances` PREVIEW the
// table expands — never a count. Rows crossing into JS stay flat at
// (distinct rule_ids × this) however large the store grows; SQLite still scans
// the table to count, so time grows with it while memory does not.
const PREVIEW_INSTANCES_PER_GROUP = 200;

// audit_events holds structural rows (session, tool_call, llm_call,
// config_scan) alongside the four capture kinds this repository's findings
// come from. Every read below joins inspection_findings to audit_events, so
// every read must constrain to this set — the old `events` table held only
// these four kinds, so this predicate is what keeps the numbers identical to
// the pre-repoint reads over `findings ⋈ events`.
const CAPTURE_EVENT_TYPES_SQL = `'prompt','response','code_change','tool_use'`;

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
 * writes the old table by name. The local store is tenant-free (single
 * tenant), so there is no tenant predicate on any query.
 */
export class SqliteFindingsRepository
  implements FindingsReadPort, DashboardViews, GroupedFindingsView
{
  constructor(private readonly db: DatabaseSync) {}

  recentFindings(opts?: { limit?: number }): Promise<FindingView[]> {
    const limit = opts?.limit ?? 50;
    const rows = allRows<FindingRowJoined>(
      this.db.prepare(
        `SELECT f.id, f.audit_event_id AS event_id, d.rule_id, d.category, d.severity,
                f.masked_match, f.action_taken, f.confidence, e.started_at AS occurred_at,
                json_extract(e.attributes, '$.source_tool') AS source_tool,
                e.event_type AS kind
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
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
   * Grouped findings for the dashboard — joins inspection_findings⋈audit_events
   * ⋈inspection_definitions (repo/file/toolName from the audit event's
   * attributes bag, rule_id/category/severity from the definition), scoped to
   * the four capture kinds (audit_events also holds structural/reconciler/scan
   * rows this list must never surface), groups by ruleId, computes
   * per-filter-excluded facets, applies the requested filters, and sorts by
   * severity then recency. Filtering
   * and faceting run in JS via the shared @akasecurity/schema helpers. `totals`
   * reflect the full filtered set; `items` is the requested
   * page (default 50); no cursor (nextCursor is always null). Under a `status`
   * filter, `totals.findings` counts only instances whose derived status was
   * requested, and each item's instance preview is narrowed the same way.
   *
   * Two reads, neither of which materializes a row per finding:
   *   1. one aggregate row per rule_id, folding EVERY instance into the numbers
   *      the group and the filters need (count, providers, actions, statuses,
   *      latest, search text);
   *   2. each group's newest PREVIEW_INSTANCES_PER_GROUP instances, which
   *      populate `instances` for the table's expanded rows.
   * The aggregates carry raw DB values and are translated by the same
   * @akasecurity/schema mappers the row path uses, so no enum mapping or status
   * rule is ever restated in SQL.
   */
  listGroupedFindings(query: ListGroupedFindingsQuery): Promise<ListGroupedFindingsResponse> {
    // The session scope is a SQL predicate, not a JS filter: totals, facets and
    // the per-group aggregates must all speak for the session only, and the
    // aggregate query never materializes a row per finding to filter in JS.
    // The capture-kind constraint is unconditional (see CAPTURE_EVENT_TYPES_SQL)
    // — audit_events carries structural/reconciler/scan rows this list must
    // never surface, the same universe the old `events` table was already
    // limited to.
    const sessionPredicate = query.sessionId ? ` AND e.root_session_id = :sessionId` : '';
    const predicate = `WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})${sessionPredicate}`;
    const sessionParams: Record<string, string> = query.sessionId
      ? { sessionId: query.sessionId }
      : {};

    // The search text is the one aggregate column whose size tracks the store
    // rather than the rule count, so fetch it only for a request that can use
    // it (see groupAggregates).
    const aggregates = this.groupAggregates(query.q !== undefined && query.q !== '', {
      predicate,
      params: sessionParams,
    });

    const rows = allRows<FindingGroupRowJoined>(
      this.db.prepare(
        `SELECT id, rule_id, category, severity, masked_match, action_taken, confidence,
                occurred_at, source_tool, repo, file, tool_name, kind, finding_key, latest_status
         FROM (
           SELECT f.id AS id, d.rule_id AS rule_id, d.category AS category,
                  d.severity AS severity, f.masked_match AS masked_match,
                  f.action_taken AS action_taken, f.confidence AS confidence,
                  e.started_at AS occurred_at,
                  json_extract(e.attributes, '$.source_tool') AS source_tool,
                  json_extract(e.attributes, '$.repo') AS repo,
                  json_extract(e.attributes, '$.file_path') AS file,
                  json_extract(e.attributes, '$.tool_name') AS tool_name,
                  e.event_type AS kind, f.finding_key AS finding_key,
                  latest.status AS latest_status,
                  ROW_NUMBER() OVER (
                    PARTITION BY d.rule_id
                    ORDER BY e.started_at DESC, f.id DESC
                  ) AS rn
             FROM inspection_findings f
             JOIN audit_events e ON e.id = f.audit_event_id
             JOIN inspection_definitions d ON d.id = f.inspection_definition_id
             LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
               ON latest.finding_key = f.finding_key
             ${predicate}
         )
         WHERE rn <= :cap
         ORDER BY occurred_at DESC, id DESC`,
      ),
      { cap: PREVIEW_INSTANCES_PER_GROUP, ...sessionParams },
    );

    const groupable: GroupableFindingRow[] = rows.map((r) => ({
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
      status: deriveInstanceStatus(r),
    }));

    // No overrides/pack names in OSS: detection.name is null, policy is
    // synthesized from category (both unused by the OSS views).
    const allGroups = buildFindingGroups(groupable, { aggregates });

    const filterOpts = {
      severity: query.severity,
      providers: query.provider,
      actions: query.action,
      statuses: query.status,
      subtype: query.subtype,
      q: query.q,
    };

    // Facets are per-filter-excluded, so compute them over the unfiltered groups.
    const facets = computeFindingFacets(allGroups, filterOpts);
    const sorted = sortFindingGroups(applyFindingFilters(allGroups, filterOpts));

    // Under a status filter, `findings` counts only the instances whose DERIVED
    // status was requested — a group folds to 'open' on the strength of a few
    // open instances, and counting its whole tally would report instances the
    // filter excluded. The per-status counts come from the aggregate's
    // statusInputs; the whole-group instanceCount is the unfiltered total.
    const statusFilter = query.status ?? [];
    const totals = {
      findings: sorted.reduce((acc, g) => {
        if (statusFilter.length === 0) return acc + g.instanceCount;
        const agg = aggregates.get(g.id);
        return (
          acc +
          (agg
            ? (countInstancesByStatus(agg.statusInputs, statusFilter) ?? g.instanceCount)
            : g.instanceCount)
        );
      }, 0),
      groups: sorted.length,
    };

    const limit = query.limit ?? DEFAULT_GROUPED_FINDINGS_LIMIT;
    // Under a status filter, narrow each group's instance PREVIEW to the
    // requested statuses so every rendered location matches the filter (the
    // group-level folds still describe the whole group). The preview holds only
    // the newest PREVIEW_INSTANCES_PER_GROUP rows, so it can end up EMPTY for a
    // group the filter correctly kept — every matching instance may be older
    // than the preview window; views render an explicit notice for that case.
    const statusSet = statusFilter.length > 0 ? new Set<string>(statusFilter) : null;
    const items = sorted.slice(0, limit).map((g) =>
      statusSet
        ? {
            ...g,
            instances: g.instances.filter((i) => i.status !== undefined && statusSet.has(i.status)),
          }
        : g,
    );

    return Promise.resolve({
      totals,
      facets,
      items,
      nextCursor: null,
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
  private groupAggregates(
    withSearchText: boolean,
    scope: { predicate: string; params: Record<string, string> },
  ): Map<string, FindingGroupAggregate> {
    // Tool names ride as their display label ("via Bash") to mirror
    // buildHaystack — see its doc for why the bare name is not searched.
    const innerSearchColumns = withSearchText
      ? `, group_concat(DISTINCT json_extract(e.attributes, '$.repo')) AS repos,
           group_concat(DISTINCT json_extract(e.attributes, '$.file_path')) AS files,
           group_concat(DISTINCT 'via ' || json_extract(e.attributes, '$.tool_name')) AS tool_names`
      : `, NULL AS repos, NULL AS files, NULL AS tool_names`;

    const rows = this.db
      .prepare(
        `SELECT rule_id,
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
                    e.event_type || '${TUPLE_SEP}' ||
                      (CASE WHEN f.finding_key IS NULL THEN '' ELSE 'k' END) || '${TUPLE_SEP}' ||
                      coalesce(latest.status, '') AS status_tuple,
                    count(*) AS tuple_count,
                    max(e.started_at) AS latest_at,
                    group_concat(DISTINCT json_extract(e.attributes, '$.source_tool')) AS source_tools,
                    group_concat(DISTINCT f.action_taken) AS actions_taken
                    ${innerSearchColumns}
               FROM inspection_findings f
               JOIN audit_events e ON e.id = f.audit_event_id
               JOIN inspection_definitions d ON d.id = f.inspection_definition_id
               LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
                 ON latest.finding_key = f.finding_key
              ${scope.predicate}
              GROUP BY d.rule_id, status_tuple
           )
          GROUP BY rule_id`,
      )
      .all(scope.params) as unknown as FindingAggregateRowJoined[];

    return new Map(
      rows.map((r) => [
        r.rule_id,
        {
          instanceCount: r.instance_count,
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
