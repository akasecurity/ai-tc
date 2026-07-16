// Shared node:sqlite query helpers for the OSS read repositories. One copy so a
// fix to LIKE escaping or bind-placeholder generation reaches every page's search
// path at once (the Data Shares and Inventory repos both build LIKE patterns and
// `IN (?, ?, …)` lists).

/**
 * Escape LIKE special characters so user search text is matched literally. Escape
 * order matters: backslash first, then % and _. Use with `LIKE ? ESCAPE '\\'`.
 */
export function escapeLikePattern(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_');
}

/** A comma-separated run of `n` bind placeholders for an `IN (…)` clause. */
export function placeholders(n: number): string {
  return Array.from({ length: n }, () => '?').join(', ');
}

/** A LIKE pattern that matches `q` anywhere, with LIKE metacharacters escaped. */
export function containsPattern(q: string): string {
  return `%${escapeLikePattern(q)}%`;
}

/**
 * A parenthesized `' OR '`-joined run of `expr LIKE ? ESCAPE '\\'` clauses, one
 * per expression. Bind one pattern (see containsPattern) per expression.
 */
export function likeAny(exprs: string[]): string {
  return `(${exprs.map((e) => `${e} LIKE ? ESCAPE '\\'`).join(' OR ')})`;
}
