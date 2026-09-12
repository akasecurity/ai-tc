// Single source of truth for the LATEST-RESOLUTION-WINS SQL used everywhere a
// finding's lifecycle status is derived from the append-only finding_resolution
// table. The rule: a key is classified by its NEWEST row only (max created_at,
// ties broken by the higher rowid so rows sharing a created_at still resolve in
// insertion order), never by "does ANY row exist" — otherwise a fixed-at-source
// key that is later redetected (the same secret re-added) would stay invisibly
// "caught" under its stale resolved row forever. See SqliteResolutionsRepository's
// class doc for the full invariant, and keep every consumer in lockstep:
//
//   - SqliteSecurityRepository.severitySummary (caught / open-at-rest buckets)
//   - SqliteSecurityRepository.mttrTrend (latest status/method/resolved_at)
//   - SqliteSecurityRepository.recentlyResolved (latest status/method/resolved_at)
//   - SqliteFindingsRepository.listGroupedFindings (per-finding status column)
//   - SqliteFindingsRepository.listFindingTypes (grouped per-rule status)
//   - SqliteFindingsRepository.listFindingInstances (per-finding status column)
//   - SqliteFindingsRepository.listFindingLocations (per-finding status column)
//   - SqliteResolutionsRepository.openAtRestKeysForPath /
//     resolvedAtRestKeysForPath (latest status)
//
// All build on these fragments so the dashboard's severity card, its MTTR
// trend, its recently-resolved feed, and its findings list can never disagree
// about which resolution row "wins".
import { EventKind, FindingStatus } from '@akasecurity/schema';

// The finding_resolution columns a correlated latest-row lookup may select —
// constrained to a union so the column name can never become an interpolated,
// unvalidated identifier.
export type ResolutionColumn = 'status' | 'method' | 'resolved_at';

/**
 * Correlated-subquery form: the latest resolution row's `column` for one
 * finding row, usable inside a SELECT list or WHERE clause. `findingsAlias`
 * is the alias of the `findings` table in the enclosing query (e.g. 'f').
 */
export function latestResolutionColumnSql(column: ResolutionColumn, findingsAlias: string): string {
  return `(
    SELECT fr.${column} FROM finding_resolution fr
     WHERE fr.finding_key = ${findingsAlias}.finding_key
     ORDER BY fr.created_at DESC, fr.rowid DESC
     LIMIT 1
  )`;
}

/** Thin wrapper over {@link latestResolutionColumnSql} for the common `status`-only case. */
export function latestResolutionStatusSql(findingsAlias: string): string {
  return latestResolutionColumnSql('status', findingsAlias);
}

/**
 * Derived-table form: one (finding_key, status, method, resolved_at) row per key
 * holding its latest resolution, for LEFT JOINing when a query aggregates over
 * many findings at once (a correlated subquery per row would re-run the lookup
 * for every finding — and per resolution column, several times per row). ROW_NUMBER
 * over (created_at DESC, rowid DESC) implements the same latest-wins ordering as
 * the correlated form; rn = 1 also makes the join safe against double-counting a
 * key that accumulated several append-only rows.
 */
export const LATEST_RESOLUTION_BY_KEY_SQL = `(
  SELECT finding_key, status, method, resolved_at FROM (
    SELECT fr.finding_key, fr.status, fr.method, fr.resolved_at,
           ROW_NUMBER() OVER (
             PARTITION BY fr.finding_key
             ORDER BY fr.created_at DESC, fr.rowid DESC
           ) AS rn
      FROM finding_resolution fr
  ) WHERE rn = 1
)`;

/**
 * SQL mirror of `deriveFindingStatus` (`@akasecurity/schema`) — the ONE
 * per-finding lifecycle classifier every read path uses — expressed as a CASE
 * expression instead of a JS function, so a grouped aggregate can facet and
 * filter on status without materializing every finding row. Same five arms,
 * same order:
 *
 *   1. `${eventsAlias}.event_type` is not the at-rest kind (`'code_change'`)
 *      → 'handled' — an in-flight capture is born handled: enforcement
 *      already ran at the boundary.
 *   2. `${findingsAlias}.finding_key` IS NULL → 'open' — a legacy at-rest row
 *      the resolution lifecycle (keyed by finding_key) can never classify.
 *   3. `latestStatusExpr` = 'resolved' → 'resolved'.
 *   4. `latestStatusExpr` = 'dismissed' → 'dismissed'.
 *   5. otherwise → 'open'.
 *
 * `latestStatusExpr` is whatever the caller wants consulted for the latest
 * resolution status — a joined alias (e.g. `latest.status`, from
 * {@link LATEST_RESOLUTION_BY_KEY_SQL}) or an inlined correlated subquery
 * (e.g. {@link latestResolutionStatusSql}) — so this fragment works in both
 * shapes the file already supports.
 *
 * TOTAL: `event_type` is NOT NULL and the final arm is unconditional, so the
 * expression can never evaluate to NULL — which is what makes a later
 * `CASE ... IN (...)` filter over it null-safe.
 *
 * NOT the same CASE as SqliteSecurityRepository.severitySummary's, on
 * purpose: that one buckets a dismissed finding as still needing remediation
 * (dismissing is a judgment, not a fix, and the severity card must never
 * understate exposure) and drops key-less rows from both of its buckets
 * entirely (they count only in its total). Copying severitySummary's CASE
 * here would misclassify both cases — this fragment answers "what status does
 * this finding show", not "does this finding still need attention".
 */
export function derivedFindingStatusSql(
  eventsAlias: string,
  findingsAlias: string,
  latestStatusExpr: string,
): string {
  return `CASE
    WHEN ${eventsAlias}.event_type != '${EventKind.enum.code_change}' THEN '${FindingStatus.enum.handled}'
    WHEN ${findingsAlias}.finding_key IS NULL THEN '${FindingStatus.enum.open}'
    WHEN ${latestStatusExpr} = '${FindingStatus.enum.resolved}' THEN '${FindingStatus.enum.resolved}'
    WHEN ${latestStatusExpr} = '${FindingStatus.enum.dismissed}' THEN '${FindingStatus.enum.dismissed}'
    ELSE '${FindingStatus.enum.open}'
  END`;
}
