// Single source of truth for the LATEST-RESOLUTION-WINS SQL used everywhere a
// finding's lifecycle status is derived from the append-only finding_resolution
// table. The rule: a key is classified by its NEWEST row only (max created_at,
// tie-broken by rowid — the SQLite twin of the Postgres `seq` tiebreak), never
// by "does ANY row exist" — otherwise a fixed-at-source key that is later
// redetected (the same secret re-added) would stay invisibly "caught" under its
// stale resolved row forever. See SqliteResolutionsRepository's class doc for
// the full invariant, and keep the two consumers in lockstep:
//
//   - SqliteSecurityRepository.severitySummary (caught / open-at-rest buckets)
//   - SqliteFindingsRepository.listGroupedFindings (per-finding status column)
//
// Both build on these fragments so the dashboard's severity card and its
// findings list can never disagree about which resolution row "wins".

/**
 * Correlated-subquery form: the latest resolution status for one finding row,
 * usable inside a SELECT list or WHERE clause. `findingsAlias` is the alias of
 * the `findings` table in the enclosing query (e.g. 'f').
 */
export function latestResolutionStatusSql(findingsAlias: string): string {
  return `(
    SELECT fr.status FROM finding_resolution fr
     WHERE fr.finding_key = ${findingsAlias}.finding_key
     ORDER BY fr.created_at DESC, fr.rowid DESC
     LIMIT 1
  )`;
}

/**
 * Derived-table form: one (finding_key, status) row per key holding its latest
 * resolution status, for LEFT JOINing when a query aggregates over many
 * findings at once (a correlated subquery per row would re-run the lookup for
 * every finding). ROW_NUMBER over (created_at DESC, rowid DESC) implements the
 * same latest-wins ordering as the correlated form; rn = 1 also makes the join
 * safe against double-counting a key that accumulated several append-only rows.
 */
export const LATEST_RESOLUTION_BY_KEY_SQL = `(
  SELECT finding_key, status FROM (
    SELECT fr.finding_key, fr.status,
           ROW_NUMBER() OVER (
             PARTITION BY fr.finding_key
             ORDER BY fr.created_at DESC, fr.rowid DESC
           ) AS rn
      FROM finding_resolution fr
  ) WHERE rn = 1
)`;
