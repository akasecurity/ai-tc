import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// Drift guard: drizzle-kit's snapshot under meta/ is its record of the schema a
// migration leaves behind, and `drizzle-kit generate` diffs the drizzle schema
// against the LATEST snapshot alone — it never reads the committed .sql. So a
// migration hand-edited to add an object, without the matching snapshot edit,
// costs nothing at apply time and makes `gen:sqlite-ddl` non-idempotent: every
// run re-diffs the same missing object and mints another migration for it.
// sqlite-ddl.test.ts cannot see this — it compares SQLITE_MIGRATIONS with the
// .sql files, and both sides of that comparison are already correct.
//
// Apply the real migrations to a real in-memory SQLite and compare the indexes
// that actually exist against the ones the latest snapshot records.
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '..', '..', 'drizzle', 'local-sqlite');

// The indexes that legitimately appear on one side only. An exact set, not a
// floor: a floor would forbid removals while letting the next drift in.
const DOCUMENTED_ONE_SIDED_INDEXES: Record<string, string> = {
  // Migrations only. An expression index over json_extract(), which drizzle's
  // schema builder cannot express, so it is hand-written in the migration and
  // is absent from every snapshot by construction.
  idx_audit_code_change_path: 'expression index, hand-written outside the drizzle schema',
  // Snapshot only. 0014 dropped the legacy `events`/`findings` TABLES and put
  // compat VIEWS of the same names in their place. The drizzle schema still
  // declares them as tables, so the snapshot goes on recording their indexes,
  // but no such index exists on a real store.
  idx_events_occurred: 'index of the legacy `events` table, replaced by a view in 0014',
  idx_findings_event: 'index of the legacy `findings` table, replaced by a view in 0014',
  uq_findings_key: 'index of the legacy `findings` table, replaced by a view in 0014',
};

interface IndexShape {
  table: string;
  columns: (string | null)[];
  unique: boolean;
  partial: boolean;
}

function journalTags(): string[] {
  const journal = JSON.parse(
    readFileSync(join(migrationsDir, 'meta', '_journal.json'), 'utf8'),
  ) as { entries: { idx: number; tag: string }[] };
  return [...journal.entries].sort((a, b) => a.idx - b.idx).map((e) => e.tag);
}

// The indexes a store really carries once every migration has been applied.
// In-memory rather than a temp dir: nothing here reads the store back through
// the product, so the file would only be a teardown to get wrong.
function indexesAfterMigrating(tags: string[]): Map<string, IndexShape> {
  const db = new DatabaseSync(':memory:');
  try {
    for (const tag of tags) {
      db.exec(readFileSync(join(migrationsDir, `${tag}.sql`), 'utf8').replace(/\r\n/g, '\n'));
    }
    const shapes = new Map<string, IndexShape>();
    // `sql IS NOT NULL` drops the implicit indexes SQLite mints for UNIQUE and
    // PRIMARY KEY constraints — no CREATE INDEX made them, so no snapshot
    // records them either.
    const rows = db
      .prepare("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")
      .all() as unknown as { name: string; tbl_name: string }[];
    for (const { name, tbl_name: table } of rows) {
      const listed = db.prepare(`PRAGMA index_list(\`${table}\`)`).all() as unknown as {
        name: string;
        unique: number;
        partial: number;
      }[];
      const meta = listed.find((r) => r.name === name);
      const columns = db.prepare(`PRAGMA index_info(\`${name}\`)`).all() as unknown as {
        name: string | null;
      }[];
      shapes.set(name, {
        table,
        // NULL for an expression column, which is what makes it one.
        columns: columns.map((c) => c.name),
        unique: meta?.unique === 1,
        partial: meta?.partial === 1,
      });
    }
    return shapes;
  } finally {
    db.close();
  }
}

// The indexes drizzle-kit believes that same chain produced.
function indexesInLatestSnapshot(tags: string[]): Map<string, IndexShape> {
  const latest = tags.at(-1);
  if (latest === undefined) throw new Error('journal has no entries');
  const snapshot = JSON.parse(
    readFileSync(join(migrationsDir, 'meta', `${latest.slice(0, 4)}_snapshot.json`), 'utf8'),
  ) as {
    tables: Record<
      string,
      { indexes?: Record<string, { columns: string[]; isUnique?: boolean; where?: string }> }
    >;
  };
  const shapes = new Map<string, IndexShape>();
  for (const [table, def] of Object.entries(snapshot.tables)) {
    for (const [name, index] of Object.entries(def.indexes ?? {})) {
      shapes.set(name, {
        table,
        columns: index.columns,
        unique: index.isUnique === true,
        // The WHERE text itself is not comparable — SQLite keeps the migration's
        // spelling while the snapshot keeps the drizzle schema's, and the two
        // render the same predicate differently. Whether the index is partial at
        // all is the part that must agree.
        partial: 'where' in index,
      });
    }
  }
  return shapes;
}

describe('drizzle snapshot vs. the migrations it claims to describe', () => {
  const tags = journalTags();
  const fromMigrations = indexesAfterMigrating(tags);
  const fromSnapshot = indexesInLatestSnapshot(tags);

  it('records every index the migrations create, and no index they do not (a mismatch here makes `pnpm --filter @akasecurity/schema gen:sqlite-ddl` mint a duplicate migration on every run)', () => {
    const oneSided = [...new Set([...fromMigrations.keys(), ...fromSnapshot.keys()])]
      .filter((name) => fromMigrations.has(name) !== fromSnapshot.has(name))
      .sort();
    expect(oneSided).toEqual(Object.keys(DOCUMENTED_ONE_SIDED_INDEXES).sort());
  });

  it('agrees with the migrations on columns, uniqueness and partiality', () => {
    for (const [name, recorded] of fromSnapshot) {
      const built = fromMigrations.get(name);
      if (!built) continue; // one-sided; pinned by the test above
      expect(built, `index ${name}`).toEqual(recorded);
    }
  });
});
