import type { DatabaseSync, SQLOutputValue } from 'node:sqlite';

const utf8 = new TextDecoder();

/**
 * The case fold the search path applies to both sides of a match: to each
 * haystack in SQL, through `aka_lower`, and to the search term in JS before it
 * is bound. One function, so the two sides cannot fold differently.
 *
 * Unicode default case mapping (`String.prototype.toLowerCase`, independent of
 * locale), the same mapping the in-memory search filters apply. SQLite's
 * built-in `lower()` folds ASCII only. The mapping has one context-sensitive
 * rule: Σ lowers to ς at the end of a word and to σ elsewhere, so a term whose
 * Σ sits in a different word position than in the haystack does not match.
 *
 * Total over every SQLite storage class, and never throws:
 *  - NULL → null
 *  - TEXT → its lowercase, embedded NULs and all
 *  - INTEGER → its decimal digits; arguments arrive as bigint, so 2^63-1 is exact
 *  - REAL → JavaScript's rendering of the number, which is not always SQLite's
 *    (`1.0` renders as `1`)
 *  - BLOB → its bytes decoded as UTF-8, invalid sequences replaced with U+FFFD
 */
export function akaLower(value: SQLOutputValue): string | null {
  if (value === null) return null;
  if (typeof value === 'string') return value.toLowerCase();
  if (typeof value === 'number' || typeof value === 'bigint') return String(value).toLowerCase();
  return utf8.decode(value).toLowerCase();
}

/**
 * Registers this package's SQL functions on `db`. The store opener calls it for
 * every connection `openLocalDatabase` opens. A connection opened any other way
 * does not carry them until this is called on it.
 *
 * `aka_lower(x)` is {@link akaLower}.
 *  - DIRECT-ONLY: SQLite refuses it inside a view, trigger, index, generated
 *    column or CHECK constraint. A function exists only on the connection that
 *    registered it, so a schema object calling it would break every connection
 *    without it, such as an older build or the sqlite3 shell.
 *  - DETERMINISTIC: SQLite evaluates it once for a constant argument.
 *  - BIGINT ARGUMENTS: an INTEGER beyond 2^53 reaches it exactly.
 */
export function registerSqlFunctions(db: DatabaseSync): void {
  db.function(
    'aka_lower',
    { deterministic: true, directOnly: true, useBigIntArguments: true },
    akaLower,
  );
}
