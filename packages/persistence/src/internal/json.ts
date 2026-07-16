// Tolerant JSON parsing for the local store's TEXT columns. Attribute bags and
// other JSON columns re-enter as strings that may be NULL, empty, or corrupt;
// these helpers never throw.

/**
 * Parse `s`, returning `fallback` for null/undefined/empty input or malformed
 * JSON. The parsed value is cast to `T` as-is — a trusted shape, not runtime
 * validation.
 */
export function safeJson<T>(s: string | null | undefined, fallback: T): T {
  if (s == null) return fallback;
  try {
    return JSON.parse(s) as T;
  } catch {
    return fallback;
  }
}

/**
 * Parse `s` and return the value only when it is a non-null object
 * (`typeof parsed === 'object' && parsed !== null`); null/undefined input,
 * malformed JSON, and scalar values yield `undefined`.
 */
export function parseJsonObject(s: string | null | undefined): Record<string, unknown> | undefined {
  if (s == null) return undefined;
  try {
    const parsed: unknown = JSON.parse(s);
    if (typeof parsed === 'object' && parsed !== null) return parsed as Record<string, unknown>;
  } catch {
    // corrupt bag → undefined
  }
  return undefined;
}
