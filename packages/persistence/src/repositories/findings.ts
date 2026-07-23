import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type {
  ActionTaken,
  DayActivity,
  DetectedFindingWithKey,
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
  toFindingRow,
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
// column (e.g. events whose metadata carries no repo).
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
 * Dedup scope for a findings write — currently the Claude session the event
 * belongs to (events carry it in `metadata.sessionId`). When a `sessionId` is
 * present, a finding whose (rule, masked value) already fired earlier in the
 * same session is skipped on write, so one sensitive value that crosses several
 * surfaces in a single action — e.g. a secret typed into a prompt and then
 * written to a file — is recorded once, not once per surface. Events without a
 * session (no `sessionId`) are never deduped: we only collapse on positive
 * evidence that two findings belong to the same flow.
 */
export interface FindingWriteScope {
  sessionId?: string;
}

/**
 * Findings table writer + the read surfaces (/findings, /health, /audit), bound
 * to one open DB. Writes take already-masked DetectedFinding[] (the raw secret
 * never reaches this layer — the SDK masks before calling). The local store is
 * tenant-free (single tenant), so there is no tenant predicate on any query.
 */
export class SqliteFindingsRepository
  implements FindingsReadPort, DashboardViews, GroupedFindingsView
{
  private readonly insertStmt: StatementSync;
  private readonly sessionDupStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // ON CONFLICT (finding_key): finding_key is nullable and UNIQUE
    // (uq_findings_key) — SQLite never equates two NULLs in a unique index, so
    // in-flight/legacy findings (findingKey null) always insert a fresh row,
    // while an at-rest finding with a real key reconciles onto its prior row
    // (same `id`, refreshed everything else) instead of duplicating — a re-scan
    // of an already-detected finding updates in place. ruleId is left out of
    // the update set: it is baked into finding_key itself, so a conflict can
    // never carry a different one.
    // first_detected_at is set ON INSERT from the finding's parent event's
    // occurred_at via a correlated subquery (the event is always inserted before
    // its findings in recordCapture, and the event_id FK guarantees it exists),
    // and is DELIBERATELY EXCLUDED from the ON CONFLICT update set — so a
    // re-detection of the same finding_key under a later event keeps the ORIGINAL
    // first-detection time (event_id/everything else refreshes; the detection
    // clock does not). This is what lets MTTR / the recently-resolved feed measure
    // from first sighting rather than the latest re-scan.
    this.insertStmt = db.prepare(
      `INSERT INTO findings (id, event_id, rule_id, category, severity, span_start, span_end, masked_match, action_taken, confidence, finding_key, first_detected_at)
       VALUES (:id, :eventId, :ruleId, :category, :severity, :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence, :findingKey,
               (SELECT occurred_at FROM events WHERE id = :eventId))
       ON CONFLICT (finding_key) DO UPDATE SET
         event_id = excluded.event_id,
         category = excluded.category,
         severity = excluded.severity,
         span_start = excluded.span_start,
         span_end = excluded.span_end,
         masked_match = excluded.masked_match,
         action_taken = excluded.action_taken,
         confidence = excluded.confidence`,
    );
    // Has this (rule, masked value) already been recorded in this session? Joins
    // to events for the session id (findings have no timestamp/session of their
    // own). Used to suppress cross-surface repeats — see FindingWriteScope.
    this.sessionDupStmt = db.prepare(
      `SELECT 1 FROM findings f JOIN events e ON e.id = f.event_id
       WHERE f.rule_id = :ruleId AND f.masked_match = :maskedMatch
         AND json_extract(e.metadata, '$.sessionId') = :sessionId
       LIMIT 1`,
    );
  }

  insertFindings(findings: DetectedFindingWithKey[], scope: FindingWriteScope = {}): void {
    for (const finding of findings) {
      if (scope.sessionId && this.isSessionDuplicate(finding, scope.sessionId)) continue;
      // Bind only the columns insertStmt's SQL names, explicitly coercing
      // findingKey's `| undefined` to `null` — node:sqlite's named-param binder
      // rejects `undefined` outright, and toFindingRow already does this
      // coercion, but bind explicitly here too so this call stays correct even
      // if a caller hands in a raw row.
      const row = toFindingRow(finding);
      this.insertStmt.run({
        id: row.id,
        eventId: row.eventId,
        ruleId: row.ruleId,
        category: row.category,
        severity: row.severity,
        spanStart: row.spanStart,
        spanEnd: row.spanEnd,
        maskedMatch: row.maskedMatch,
        actionTaken: row.actionTaken,
        confidence: row.confidence,
        findingKey: row.findingKey ?? null,
      });
    }
  }

  // True when an earlier event in the same session already recorded a finding
  // with the same rule and masked value. The current event is inserted before
  // its findings, but carries no findings yet, so this never self-matches.
  private isSessionDuplicate(finding: DetectedFindingWithKey, sessionId: string): boolean {
    const hit = this.sessionDupStmt.get({
      ruleId: finding.ruleId,
      maskedMatch: finding.maskedMatch,
      sessionId,
    });
    return hit !== undefined;
  }

  recentFindings(opts?: { limit?: number }): Promise<FindingView[]> {
    const limit = opts?.limit ?? 50;
    const rows = allRows<FindingRowJoined>(
      this.db.prepare(
        `SELECT f.id, f.event_id, f.rule_id, f.category, f.severity, f.masked_match,
                f.action_taken, f.confidence, e.occurred_at, e.source_tool, e.kind
         FROM findings f JOIN events e ON e.id = f.event_id
         ORDER BY e.occurred_at DESC, f.rowid DESC
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
   * session-stamped events (served by idx_events_session_id), so the Activity
   * page can label its findings link without the grouped pipeline. */
  sessionFindingsCount(sessionId: string): Promise<number> {
    if (!sessionId) return Promise.resolve(0);
    return Promise.resolve(
      countScalar(
        this.db,
        `SELECT count(*) AS n FROM findings f
           JOIN events e ON e.id = f.event_id
          WHERE json_extract(e.metadata, '$.sessionId') = :sessionId`,
        { sessionId },
      ),
    );
  }

  /** Per-rule transcript firing tally for one session — reads the OTHER finding
   * store (inspection_findings, keyed to audit_events): every detection the
   * transcript pass recorded, counted per firing rather than per unique value.
   * Rides on session-scoped grouped responses so the findings view can
   * reconcile the Activity page's tally with the deduped groups it lists. */
  private sessionFirings(sessionId: string): Record<string, number> {
    return Object.fromEntries(
      countBy(
        this.db,
        `SELECT d.rule_id AS k, count(*) AS n
           FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id
          WHERE e.root_session_id = :sessionId
          GROUP BY d.rule_id`,
        { sessionId },
      ),
    );
  }

  /**
   * Grouped findings for the dashboard — joins findings⋈events (repo/file/
   * toolName from event metadata), groups by ruleId, computes per-filter-excluded facets,
   * applies the requested filters, and sorts by severity then recency. Filtering
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
    const sessionPredicate = query.sessionId
      ? `WHERE json_extract(e.metadata, '$.sessionId') = :sessionId`
      : '';
    const sessionParams: Record<string, string> = query.sessionId
      ? { sessionId: query.sessionId }
      : {};

    // The search text is the one aggregate column whose size tracks the store
    // rather than the rule count, so fetch it only for a request that can use
    // it (see groupAggregates).
    const aggregates = this.groupAggregates(query.q !== undefined && query.q !== '', {
      predicate: sessionPredicate,
      params: sessionParams,
    });

    const rows = allRows<FindingGroupRowJoined>(
      this.db.prepare(
        `SELECT id, rule_id, category, severity, masked_match, action_taken, confidence,
                occurred_at, source_tool, repo, file, tool_name, kind, finding_key, latest_status
         FROM (
           SELECT f.id AS id, f.rule_id AS rule_id, f.category AS category,
                  f.severity AS severity, f.masked_match AS masked_match,
                  f.action_taken AS action_taken, f.confidence AS confidence,
                  e.occurred_at AS occurred_at, e.source_tool AS source_tool,
                  json_extract(e.metadata, '$.repo') AS repo,
                  json_extract(e.metadata, '$.filePath') AS file,
                  json_extract(e.metadata, '$.toolName') AS tool_name,
                  e.kind AS kind, f.finding_key AS finding_key,
                  latest.status AS latest_status,
                  ROW_NUMBER() OVER (
                    PARTITION BY f.rule_id
                    ORDER BY e.occurred_at DESC, f.id DESC
                  ) AS rn
             FROM findings f
             JOIN events e ON e.id = f.event_id
             LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
               ON latest.finding_key = f.finding_key
             ${sessionPredicate}
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
      ? `, group_concat(DISTINCT json_extract(e.metadata, '$.repo')) AS repos,
           group_concat(DISTINCT json_extract(e.metadata, '$.filePath')) AS files,
           group_concat(DISTINCT 'via ' || json_extract(e.metadata, '$.toolName')) AS tool_names`
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
             SELECT f.rule_id AS rule_id,
                    e.kind || '${TUPLE_SEP}' ||
                      (CASE WHEN f.finding_key IS NULL THEN '' ELSE 'k' END) || '${TUPLE_SEP}' ||
                      coalesce(latest.status, '') AS status_tuple,
                    count(*) AS tuple_count,
                    max(e.occurred_at) AS latest_at,
                    group_concat(DISTINCT e.source_tool) AS source_tools,
                    group_concat(DISTINCT f.action_taken) AS actions_taken
                    ${innerSearchColumns}
               FROM findings f
               JOIN events e ON e.id = f.event_id
               LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
                 ON latest.finding_key = f.finding_key
              ${scope.predicate}
              GROUP BY f.rule_id, status_tuple
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
    const total = countScalar(this.db, 'SELECT count(*) AS n FROM findings');
    const byAction = Object.fromEntries(ACTION_TAKEN_KEYS.map((a) => [a, 0])) as Record<
      ActionTaken,
      number
    >;
    const grouped = allRows<{ action_taken: string; c: number }>(
      this.db.prepare('SELECT action_taken, count(*) AS c FROM findings GROUP BY action_taken'),
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
        `SELECT f.severity AS severity, count(*) AS c
         FROM findings f
         LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
           ON latest.finding_key = f.finding_key
         WHERE latest.status IS NULL OR latest.status != 'resolved'
         GROUP BY f.severity`,
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
        `SELECT date(e.occurred_at / 1000, 'unixepoch') AS day, f.action_taken AS action, count(*) AS c
         FROM findings f JOIN events e ON e.id = f.event_id
         WHERE e.occurred_at >= :since
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
