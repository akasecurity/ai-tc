// --- migration-DDL introspection --------------------------------------------
// drizzle's generated SQLite DDL is rigidly formatted — backtick-quoted
// identifiers, one statement per `--> statement-breakpoint` — which is what
// makes the light parsing below safe.

import type { DatabaseSync } from 'node:sqlite';

// A schema object whose EXISTENCE proves its migration already ran: tables and
// ADDed columns. Indexes are deliberately NOT evidence — divergent stores have
// gained columns without their index (the ensureTokenUsageColumns backfill
// adds the 0001 token columns but not `idx_audit_session_type`) — and unlike
// tables/columns their DDL is safely re-runnable, so applyMigrations handles
// them per statement instead.
export type EvidenceObject =
  { kind: 'table'; name: string } | { kind: 'column'; table: string; name: string };

export function evidenceObjects(sql: string): EvidenceObject[] {
  const objects: EvidenceObject[] = [];
  for (const m of sql.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?`([^`]+)`/g)) {
    // drizzle's table-recreate creates a transient `__new_<table>` that is
    // renamed away before the migration ends — it can never prove the
    // migration ran (a recreate-only migration probes as never-applied and
    // would replay on every unledgered reconcile), and a LEFTOVER __new_ table
    // from an interrupted out-of-band push would falsely adopt it. Not
    // evidence, either way.
    if (m[1] !== undefined && !m[1].startsWith('__new_')) {
      objects.push({ kind: 'table', name: m[1] });
    }
  }
  for (const m of sql.matchAll(/ALTER TABLE `([^`]+)` ADD (?:COLUMN )?`([^`]+)`/g)) {
    if (m[1] !== undefined && m[2] !== undefined) {
      objects.push({ kind: 'column', table: m[1], name: m[2] });
    }
  }
  return objects;
}

/**
 * True when a schema object of `kind` named `name` exists in sqlite_master.
 * `kind` distinguishes a real table from a same-named VIEW — sqlite_master
 * tags them with different `type` values, so a probe for `'table'` correctly
 * reports false once a dropped-then-viewed name (e.g. the legacy `events`/
 * `findings` compatibility views) is no longer a real table.
 */
export function schemaObjectExists(
  db: DatabaseSync,
  kind: 'table' | 'index' | 'view',
  name: string,
): boolean {
  const row = db
    .prepare('SELECT 1 FROM sqlite_master WHERE type = ? AND name = ? LIMIT 1')
    .get(kind, name);
  return row !== undefined;
}

/** True when an index named `name` exists. */
export function indexExists(db: DatabaseSync, name: string): boolean {
  return schemaObjectExists(db, 'index', name);
}

/**
 * The indexed column names of `name`, in index order. Empty for an index that
 * does not exist.
 *
 * WHY A MIGRATION NEEDS THIS. `CREATE INDEX IF NOT EXISTS` matches on the NAME
 * alone: against a store that already holds an index of that name it is a
 * silent no-op, whatever columns the statement asks for. So widening an
 * existing index's column list by editing its `CREATE` reaches only stores that
 * have never seen it — every upgraded store keeps the narrow one, the read it
 * was widened for falls back to a scan, and no test that builds a fresh store
 * can tell. Widening therefore means DROP-then-CREATE, and DROP-then-CREATE
 * inside a migration that runs on every database open means rebuilding the
 * index on every open. Comparing against what is actually there is what makes
 * the rebuild happen once.
 *
 * PRAGMA index_info, NOT index_xinfo: xinfo also lists the rowid the index
 * carries internally, as a trailing entry whose name is null, so a caller
 * comparing its output to a column list would never match. PRAGMA cannot be
 * parameterized; the name comes from our own committed DDL constants.
 */
export function indexColumns(db: DatabaseSync, name: string): string[] {
  if (!indexExists(db, name)) return [];
  const columns = db.prepare(`PRAGMA index_info(${name})`).all() as { name: string | null }[];
  return columns.map((c) => c.name).filter((c): c is string => c !== null);
}

/**
 * The column names of `table`. `includeGenerated` probes with PRAGMA
 * table_xinfo, which sees generated columns; the default PRAGMA table_info
 * omits them. PRAGMA can't be parameterized; the table name comes from our own
 * committed DDL constants. A missing table yields an empty list.
 */
export function columnNames(
  db: DatabaseSync,
  table: string,
  opts?: { includeGenerated?: boolean },
): string[] {
  const pragma = opts?.includeGenerated ? 'table_xinfo' : 'table_info';
  const columns = db.prepare(`PRAGMA ${pragma}(${table})`).all() as { name: string }[];
  return columns.map((c) => c.name);
}

export function evidenceExists(db: DatabaseSync, object: EvidenceObject): boolean {
  if (object.kind === 'column') {
    // table_xinfo, NOT table_info: generated columns are invisible to table_info,
    // so probing with it would call every token-usage column missing. A missing
    // table yields an empty row set — the column counts as absent.
    return columnNames(db, object.table, { includeGenerated: true }).includes(object.name);
  }
  return schemaObjectExists(db, 'table', object.name);
}
