// Typed row access over node:sqlite statements. The single audited cast from
// the driver's Record<string, SQLOutputValue> rows to the caller's row type
// lives here, alongside the bind/scalar conventions the repositories share.

import type { DatabaseSync, SQLInputValue, StatementSync } from 'node:sqlite';

/** Bind parameters: a named-parameter object or a positional array. */
export type BindParams = Record<string, SQLInputValue> | SQLInputValue[];

/** All rows of `stmt`, cast to the caller's row type `T`. */
export function allRows<T>(stmt: StatementSync, params?: BindParams): T[] {
  if (params === undefined) return stmt.all() as unknown as T[];
  if (Array.isArray(params)) return stmt.all(...params) as unknown as T[];
  return stmt.all(params) as unknown as T[];
}

/** The first row of `stmt` (or undefined), cast to the caller's row type `T`. */
// `T` appears only in the return type on purpose: the caller names the row
// shape and the audited cast to it happens here instead of at every call site.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
export function getRow<T>(stmt: StatementSync, params?: BindParams): T | undefined {
  if (params === undefined) return stmt.get() as unknown as T | undefined;
  if (Array.isArray(params)) return stmt.get(...params) as unknown as T | undefined;
  return stmt.get(params) as unknown as T | undefined;
}

/** A raw json_extract boolean comes back as 1/0 (or null); normalize to bool. */
export function intToBool(raw: unknown): boolean {
  return raw === 1 || raw === true;
}

/** A JS boolean as the 0/1 integer SQLite stores. */
export function boolToInt(b: boolean): 0 | 1 {
  return b ? 1 : 0;
}

/**
 * A named-parameter bag safe to bind: every `undefined` property becomes null
 * (node:sqlite rejects undefined); every other value passes through.
 */
export function bindParams(
  row: Record<string, SQLInputValue | undefined>,
): Record<string, SQLInputValue> {
  const out: Record<string, SQLInputValue> = {};
  for (const [key, value] of Object.entries(row)) {
    out[key] = value === undefined ? null : value;
  }
  return out;
}

/**
 * The scalar of a count query whose result column is aliased `AS n`; `0` when
 * the query yields no row.
 */
export function countScalar(db: DatabaseSync, sql: string, params?: BindParams): number {
  return getRow<{ n: number }>(db.prepare(sql), params)?.n ?? 0;
}

/**
 * The rows of a grouped count query — group key aliased `AS k`, count aliased
 * `AS n` — as a key → count Map.
 */
export function countBy(db: DatabaseSync, sql: string, params?: BindParams): Map<string, number> {
  const map = new Map<string, number>();
  for (const row of allRows<{ k: string; n: number }>(db.prepare(sql), params)) {
    map.set(row.k, row.n);
  }
  return map;
}

/** Map each row with `map`; a row whose `map` throws is skipped. */
export function mapRowsTolerant<R, T>(rows: R[], map: (row: R) => T): T[] {
  const out: T[] = [];
  for (const row of rows) {
    try {
      out.push(map(row));
    } catch {
      // A malformed row is skipped rather than failing the whole read.
    }
  }
  return out;
}
