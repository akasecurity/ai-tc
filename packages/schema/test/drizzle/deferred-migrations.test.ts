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

describe('DEFERRED_MIGRATION_TAGS', () => {
  it('names only migrations that exist', () => {
    const tags = new Set(SQLITE_MIGRATIONS.map((m) => m.tag));
    for (const tag of DEFERRED_MIGRATION_TAGS) {
      expect(tags.has(tag), `${tag} is not in SQLITE_MIGRATIONS`).toBe(true);
    }
  });

  // A skipped migration that also added a column or a table would leave every
  // reader of it broken on a store a hook opened. Only an index can be absent
  // without changing what a read returns, and only because each reader carries
  // a fallback for it.
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

  // A migration added after these is applied on a hook open while they are
  // skipped, so it must not depend on any of their indexes. Keeping the set at
  // the end of the array makes adding one a failure here, which is the prompt
  // to decide that rather than discover it. (This is array order: the applier
  // runs the legacy-drop migration after its loop, so the LEDGER ends there.)
  it('sits at the end of SQLITE_MIGRATIONS', () => {
    const tail = SQLITE_MIGRATIONS.slice(-DEFERRED_MIGRATION_TAGS.length).map((m) => m.tag);
    expect(tail).toEqual([...DEFERRED_MIGRATION_TAGS]);
  });
});
