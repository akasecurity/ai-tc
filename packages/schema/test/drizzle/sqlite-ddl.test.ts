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

function readSourceMigrations(): { tag: string; sql: string }[] {
  const journal = JSON.parse(
    readFileSync(join(migrationsDir, 'meta', '_journal.json'), 'utf8'),
  ) as {
    entries: JournalEntry[];
  };
  return [...journal.entries]
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
