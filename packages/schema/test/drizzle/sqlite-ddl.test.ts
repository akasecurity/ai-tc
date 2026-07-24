import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SQLITE_MIGRATIONS } from '../../src/drizzle/sqlite-ddl.ts';

// Drift guard: SQLITE_MIGRATIONS is a committed, bundling-safe copy of the OSS
// local store's drizzle-kit output (drizzle/local-sqlite, generated from the
// tenant-free schema src/drizzle/local/sqlite.ts). Re-read the source .sql files
// here and assert the constant still matches, so a regenerated migration that
// nobody copied over fails CI instead of silently shipping a stale schema.
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '..', '..', 'drizzle', 'local-sqlite');

interface JournalEntry {
  idx: number;
  tag: string;
}

function readJournalEntries(): JournalEntry[] {
  return (
    JSON.parse(readFileSync(join(migrationsDir, 'meta', '_journal.json'), 'utf8')) as {
      entries: JournalEntry[];
    }
  ).entries;
}

function readSourceMigrations(): { tag: string; sql: string }[] {
  return [...readJournalEntries()]
    .sort((a, b) => a.idx - b.idx)
    .map((e) => ({
      tag: e.tag,
      // The guard compares SQL content, not checkout line endings — a CRLF
      // working tree (e.g. git autocrlf on Windows) must still compare equal.
      sql: readFileSync(join(migrationsDir, `${e.tag}.sql`), 'utf8').replace(/\r\n/g, '\n'),
    }));
}

describe('SQLITE_MIGRATIONS', () => {
  it('matches the OSS local-store drizzle SQLite migrations exactly (run `pnpm --filter @akasecurity/schema gen:sqlite-ddl` if this fails)', () => {
    expect(SQLITE_MIGRATIONS).toEqual(readSourceMigrations());
  });

  it('is ordered by journal idx (apply order)', () => {
    const tags = SQLITE_MIGRATIONS.map((m) => m.tag);
    expect(tags).toEqual([...tags].sort());
  });

  // A stack cut before a since-merged migration and then rebased/merged forward
  // can re-use an idx (two migrations at the same idx) — a collision the
  // ordered-by-tag test above does NOT catch, because lexically sorted tags can
  // still equal themselves. Assert the journal's idx values are unique and
  // contiguous from 0 so a renumber collision fails CI instead of silently
  // shipping a forked drizzle snapshot lineage.
  it('journal idx values are unique and contiguous from 0', () => {
    const idxs = readJournalEntries()
      .map((e) => e.idx)
      .sort((a, b) => a - b);
    expect(new Set(idxs).size).toBe(idxs.length); // no duplicate idx
    expect(idxs).toEqual(idxs.map((_, i) => i)); // 0,1,2,… no gap
  });

  it('every journal tag has a migration .sql file on disk (renumber leaves no orphan tag)', () => {
    for (const e of readJournalEntries()) {
      expect(() => readFileSync(join(migrationsDir, `${e.tag}.sql`), 'utf8')).not.toThrow();
    }
  });

  it('contains no carriage returns (generator EOL-normalizes)', () => {
    for (const m of SQLITE_MIGRATIONS) {
      expect(m.sql).not.toContain('\r');
    }
  });

  it('creates the tenant-free tables the local store relies on', () => {
    const all = SQLITE_MIGRATIONS.map((m) => m.sql).join('\n');
    for (const table of [
      'events',
      'findings',
      'policies',
      'installed_packs',
      'exceptions',
      // Meta data model (tenant-free local mirror).
      'inventory',
      'source_project',
      'audit_events',
      'classified_data',
      'inspection_definitions',
      'inspection_findings',
    ]) {
      expect(all).toContain(`CREATE TABLE \`${table}\``);
    }
  });

  it('is tenant-free: no tenant_id/user_id columns, no tenants/users/auth tables', () => {
    const all = SQLITE_MIGRATIONS.map((m) => m.sql).join('\n');
    expect(all).not.toContain('tenant_id');
    expect(all).not.toContain('user_id');
    for (const table of ['tenants', 'users', 'account', 'session', 'verification']) {
      expect(all).not.toContain(`CREATE TABLE \`${table}\``);
    }
  });
});
