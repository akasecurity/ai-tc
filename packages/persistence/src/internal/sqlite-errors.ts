// Shared classification of node:sqlite errors.

// node:sqlite surfaces constraint violations as ERR_SQLITE_ERROR carrying the
// SQLite extended result code; 2067 is SQLITE_CONSTRAINT_UNIQUE.
export const SQLITE_CONSTRAINT_UNIQUE = 2067;

/** True when `err` is a SQLite UNIQUE-constraint violation. */
export function isUniqueConstraintError(err: unknown): boolean {
  return (
    err instanceof Error &&
    ((err as { errcode?: number }).errcode === SQLITE_CONSTRAINT_UNIQUE ||
      err.message.includes('UNIQUE constraint failed'))
  );
}
