// Pure ISO-8601 <-> epoch-millis helpers.
// NO drizzle import. Used by the persistence layer at the SQLite query boundary.

/**
 * Convert an ISO-8601 datetime string to epoch milliseconds (integer).
 * Used before writing `occurred_at` / `created_at` to SQLite.
 */
export function isoToEpochMillis(iso: string): number {
  return new Date(iso).getTime();
}

/**
 * Convert epoch milliseconds to an ISO-8601 datetime string.
 * Used when reading `occurred_at` / `created_at` from SQLite
 * so values re-enter Zod as valid `z.string().datetime()`.
 */
export function epochMillisToIso(ms: number): string {
  return new Date(ms).toISOString();
}
