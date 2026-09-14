import { describe, expect, it } from 'vitest';

import { DEFERRED_MIGRATION_TAGS } from '../../src/drizzle/deferred-migrations.ts';
import { SQLITE_MIGRATIONS } from '../../src/drizzle/sqlite-ddl.ts';

const DEFERRED = new Set<string>(DEFERRED_MIGRATION_TAGS);

/** A migration's statements, with leading SQL line comments stripped and empty segments dropped. */
function statementsOf(sql: string): string[] {
  return sql
    .split(/-->\s*statement-breakpoint/)
    .map((statement) => statement.replace(/^(?:\s*--[^\n]*\n?)+/, '').trim())
    .filter((statement) => statement !== '');
}

/** The index names a migration creates. */
function indexesCreatedBy(sql: string): string[] {
  return [...sql.matchAll(/CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?`([^`]+)`/g)].map(
    (match) => match[1] ?? '',
  );
}

/** The tables a migration's CREATE INDEX statements build on. */
function tablesIndexedBy(sql: string): string[] {
  return [...sql.matchAll(/CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?`[^`]+` ON `([^`]+)`/g)].map(
    (match) => match[1] ?? '',
  );
}

/**
 * The statements in `sql` that would take one of `indexes` away: dropping a
 * table in `tables`, renaming one away, or dropping one of the indexes by name.
 */
function removalsIn(
  sql: string,
  tables: ReadonlySet<string>,
  indexes: ReadonlySet<string>,
): string[] {
  return statementsOf(sql).filter((statement) => {
    const droppedTable = /^DROP TABLE (?:IF EXISTS )?`?([^`\s;]+)`?/.exec(statement)?.[1];
    const renamedTable = /^ALTER TABLE `?([^`\s]+)`? RENAME TO /.exec(statement)?.[1];
    const droppedIndex = /^DROP INDEX (?:IF EXISTS )?`?([^`\s;]+)`?/.exec(statement)?.[1];
    return (
      (droppedTable !== undefined && tables.has(droppedTable)) ||
      (renamedTable !== undefined && tables.has(renamedTable)) ||
      (droppedIndex !== undefined && indexes.has(droppedIndex))
    );
  });
}

describe('DEFERRED_MIGRATION_TAGS', () => {
  it('names only migrations that exist', () => {
    const tags = new Set(SQLITE_MIGRATIONS.map((m) => m.tag));
    for (const tag of DEFERRED_MIGRATION_TAGS) {
      expect(tags.has(tag), `${tag} is not in SQLITE_MIGRATIONS`).toBe(true);
    }
  });

  // A skipped migration that also added a column or a table would leave every
  // reader of it broken on a store a hook opened. Only an index can be absent
  // without changing what a read returns, and only if each read that names it
  // carries a fallback for it.
  it('names only migrations made entirely of CREATE INDEX statements', () => {
    for (const tag of DEFERRED_MIGRATION_TAGS) {
      const migration = SQLITE_MIGRATIONS.find((m) => m.tag === tag);
      const statements = statementsOf(migration?.sql ?? '');
      expect(statements.length, `${tag} has no statements`).toBeGreaterThan(0);
      for (const statement of statements) {
        expect(statement, `${tag}: ${statement.slice(0, 80)}`).toMatch(
          /^CREATE (?:UNIQUE )?INDEX /,
        );
      }
    }
  });

  // The applier builds any index a migration names that the store lacks, so a
  // later migration re-emitting one of these names would rebuild it on the hook
  // path with no deferred ledger row to stop it.
  it('shares no index with any migration outside the set', () => {
    const deferredIndexes = new Set(
      SQLITE_MIGRATIONS.filter((m) => DEFERRED.has(m.tag)).flatMap((m) => indexesCreatedBy(m.sql)),
    );
    // The positive control: without it an extraction regex that matched nothing
    // would report no overlap for every input.
    expect(deferredIndexes.size).toBeGreaterThanOrEqual(DEFERRED_MIGRATION_TAGS.length);

    for (const migration of SQLITE_MIGRATIONS) {
      if (DEFERRED.has(migration.tag)) continue;
      for (const name of indexesCreatedBy(migration.sql)) {
        expect(
          deferredIndexes.has(name),
          `${migration.tag} re-creates deferred index ${name}`,
        ).toBe(false);
      }
    }
  });

  // A migration after the deferred ones runs on a hook open while they are
  // skipped, and on an opted-in store after they are ledgered. The applier never
  // re-runs a ledgered migration, so a later migration that removes one of their
  // indexes removes it for good on every store that had built it. A drizzle
  // table-recreate does exactly that: it drops the table, taking its indexes
  // with it. Adding a column, or any migration on another table, stays legal.
  it('no later migration drops or renames a table they index, or drops one of their indexes', () => {
    const deferred = SQLITE_MIGRATIONS.filter((m) => DEFERRED.has(m.tag));
    const tables = new Set(deferred.flatMap((m) => tablesIndexedBy(m.sql)));
    const indexes = new Set(deferred.flatMap((m) => indexesCreatedBy(m.sql)));
    const someIndex = [...indexes][0] ?? '';

    // Positive controls: the extraction found the tables, and the detector
    // recognises each shape it guards against, so a pattern that matched nothing
    // cannot pass every migration below.
    expect(tables.has('audit_events')).toBe(true);
    expect(removalsIn('DROP TABLE `audit_events`;', tables, indexes)).toHaveLength(1);
    expect(
      removalsIn('ALTER TABLE `audit_events` RENAME TO `audit_events_old`;', tables, indexes),
    ).toHaveLength(1);
    expect(removalsIn(`DROP INDEX IF EXISTS \`${someIndex}\`;`, tables, indexes)).toHaveLength(1);
    expect(removalsIn('ALTER TABLE `audit_events` ADD `extra` text;', tables, indexes)).toEqual([]);

    const first = SQLITE_MIGRATIONS.findIndex((m) => DEFERRED.has(m.tag));
    expect(first).toBeGreaterThanOrEqual(0);
    for (const migration of SQLITE_MIGRATIONS.slice(first + 1)) {
      if (DEFERRED.has(migration.tag)) continue;
      expect(removalsIn(migration.sql, tables, indexes), migration.tag).toEqual([]);
    }
  });
});
