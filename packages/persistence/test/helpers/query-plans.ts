/**
 * What SQLite decides to do with a read, taken from the read ITSELF.
 *
 * A query plan is only worth asserting on if the SQL it describes is the SQL
 * the product runs. Restating a repository's query in a test gives a second
 * model of it, free to drift the moment someone edits the first — and a plan
 * assertion over drifted SQL is the most convincing kind of green there is,
 * because it reports a real plan for a real query that no user ever issues.
 *
 * So nothing here spells a query. `recordingConnection` wraps a `DatabaseSync`
 * and hands the repositories a stand-in whose `prepare` returns a statement
 * that remembers the SQL and the parameters each `all`/`get`/`run` was actually
 * called with. Drive the read surface, and what comes back is what ran.
 *
 * Capturing the PARAMETERS matters as much as capturing the SQL. `EXPLAIN QUERY
 * PLAN` re-prepares the statement, and node:sqlite refuses to execute one whose
 * parameters are unbound — so a recorder that kept only the text could explain
 * the queries that take none and would throw on every other one. Worse, the plan
 * can DEPEND on the values: SQLite's `LIKE` optimization and its handling of a
 * range bound both turn on what is bound, so explaining with invented parameters
 * can report an index the real call never gets.
 *
 * One property is load-bearing and easy to lose. A repository may prepare a
 * statement in its CONSTRUCTOR and execute it later — several in this package
 * do — so the recorder attaches to `prepare` and records at EXECUTION, not at
 * prepare time. Recording at prepare time would report every statement a
 * constructor builds, including the ones the driven read never runs, and would
 * miss which parameters it ran with.
 */
import type { DatabaseSync, StatementSync } from 'node:sqlite';

/** One statement execution: the SQL, and the arguments it was called with. */
export interface RecordedQuery {
  readonly sql: string;
  /** Exactly what was passed to `all`/`get`/`run` — spread back in to re-run it. */
  readonly args: readonly unknown[];
}

/** One row of `EXPLAIN QUERY PLAN`, as the driver returns it. */
export interface PlanRow {
  readonly id: number;
  readonly parent: number;
  readonly detail: string;
}

/** A host method reached through a proxy, callable and bound to its own object. */
type HostMethod = (...args: unknown[]) => unknown;

/**
 * A property read straight through to the real object.
 *
 * `DatabaseSync` and `StatementSync` are native objects that reject a proxy as
 * their receiver, and that bites in TWO places, not one:
 *
 *  - a METHOD handed back loose throws `Illegal invocation` the moment a
 *    repository calls it, so it is re-bound to its own target;
 *  - an ACCESSOR (`db.isOpen`, `stmt.sourceSQL`) throws the same way at the
 *    read itself, because the getter runs with whatever receiver is passed. So
 *    the target is the receiver here — the proxy is deliberately NOT forwarded.
 *    Passing it through is the shape that reads correct and fails on the first
 *    getter anyone touches.
 */
function passThrough(target: object, prop: string | symbol): unknown {
  const value: unknown = Reflect.get(target, prop, target);
  return typeof value === 'function' ? (value as HostMethod).bind(target) : value;
}

/**
 * A `DatabaseSync` stand-in that appends to `into` every time a statement it
 * prepared is executed.
 *
 * Returned as `DatabaseSync` because that is what the repository constructors
 * take. It is a proxy, not a subclass — `DatabaseSync` is a host object with no
 * useful constructor to extend — so anything the repositories reach for beyond
 * `prepare` passes straight through to the real connection.
 */
export function recordingConnection(db: DatabaseSync, into: RecordedQuery[]): DatabaseSync {
  return new Proxy(db, {
    get(target, prop) {
      if (prop !== 'prepare') return passThrough(target, prop);
      return (sql: string): StatementSync => {
        const stmt = target.prepare(sql);
        return new Proxy(stmt, {
          get(stmtTarget, stmtProp) {
            if (stmtProp !== 'all' && stmtProp !== 'get' && stmtProp !== 'run') {
              return passThrough(stmtTarget, stmtProp);
            }
            const value: unknown = Reflect.get(stmtTarget, stmtProp, stmtTarget);
            if (typeof value !== 'function') return value;
            return (...args: unknown[]): unknown => {
              into.push({ sql, args });
              return (value as HostMethod).apply(stmtTarget, args);
            };
          },
        });
      };
    },
  });
}

/**
 * `EXPLAIN QUERY PLAN` for one recorded execution, run against `db` with the
 * same arguments the real call used.
 */
export function explain(db: DatabaseSync, query: RecordedQuery): PlanRow[] {
  const stmt = db.prepare(`EXPLAIN QUERY PLAN ${query.sql}`);
  return (query.args.length > 0
    ? stmt.all(...(query.args as never[]))
    : stmt.all()) as unknown as PlanRow[];
}

/**
 * What one plan row does, in the only three flavours a budget cares about.
 *
 *  - `full-table` — `SCAN <t>` with no index named. Every row, every column,
 *    straight off the b-tree. The thing the acceptance criterion bans.
 *  - `full-index` — `SCAN <t> USING [COVERING] INDEX <i>`. Still every row, but
 *    read in index order. Cheaper per row and often the RIGHT plan for a
 *    whole-table aggregate, so it is not a defect — but it is O(rows), which is
 *    what makes a dashboard read grow with the store, so it is tracked rather
 *    than ignored.
 *  - `search` — an indexed lookup or range. Sub-linear; nothing to say about it.
 *
 * Anything else (`MATERIALIZE`, `CO-ROUTINE`, `USE TEMP B-TREE`, a `SCAN` of a
 * subquery) is `other`. A subquery scan is a consequence of whatever is scanned
 * beneath it, not an independent cost, and SQLite prints those parenthesized
 * (`SCAN (subquery-4)`), which is how they are told apart from a base table.
 */
export type PlanKind = 'full-table' | 'full-index' | 'search' | 'other';

export interface PlanStep {
  readonly kind: PlanKind;
  /**
   * What this step passes over in full, for `full-table`/`full-index`.
   *
   * For `full-index` it is the real base table, resolved from the INDEX name via
   * `sqlite_master` and never from the text before it — SQLite prints the
   * query's ALIAS there (`SCAN v USING INDEX idx_secret_vault_last_seen`), so
   * reading that would report a table called `v`. An index name is unambiguous
   * and the lookup is against the live schema, so a renamed index cannot quietly
   * stop resolving.
   *
   * For `full-table` there is no index to resolve through, so this is the name
   * as SQLite printed it — which IS the alias when the query used one. That is
   * enough, because nothing pins this case: it is banned outright, and the name
   * only has to be good enough to name in the failure.
   */
  readonly table?: string;
  readonly detail: string;
}

/** index name → the table it belongs to, from the live schema. */
export function indexOwners(db: DatabaseSync): Map<string, string> {
  const rows = db
    .prepare(`SELECT name, tbl_name FROM sqlite_master WHERE type = 'index'`)
    .all() as unknown as { name: string; tbl_name: string }[];
  return new Map(rows.map((r) => [r.name, r.tbl_name]));
}

export function classifyPlanRow(detail: string, owners: ReadonlyMap<string, string>): PlanStep {
  const text = detail.trim();

  const indexScan = /^SCAN\b.*\bUSING (?:COVERING )?INDEX (\S+)/.exec(text);
  if (indexScan) {
    const index = indexScan[1];
    // An index name that resolves to no table means the schema moved under this
    // helper. Reported as `other` with no table rather than attributed to the
    // alias, so a pinned set can never gain a phantom entry — and the read's
    // own assertion still sees the step, because a pinned set is compared
    // exactly and a step that vanished from it fails too.
    const table = index === undefined ? undefined : owners.get(index);
    if (table !== undefined) return { kind: 'full-index', table, detail: text };
    return { kind: 'other', detail: text };
  }

  if (text.startsWith('SEARCH')) return { kind: 'search', detail: text };

  // `SCAN <name>` with nothing after it. Parenthesized names are derived
  // (subquery/CTE); a bare one is a base table or an alias of one, and either
  // way it is the unindexed full pass the criterion bans.
  const bare = /^SCAN (?!\()(\S+)(?: AS (\S+))?$/.exec(text);
  const scanned = bare?.[1];
  if (scanned !== undefined) return { kind: 'full-table', table: scanned, detail: text };

  return { kind: 'other', detail: text };
}
