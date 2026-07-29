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
//   - SqliteResolutionsRepository.openAtRestKeysForPath /
//     resolvedAtRestKeysForPath (latest status)
//
// All build on these fragments so the dashboard's severity card, its MTTR
// trend, its recently-resolved feed, and its findings list can never disagree
// about which resolution row "wins".

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
