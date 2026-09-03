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
// Apply the real migrations to a real in-memory SQLite and compare the tables,
// columns and indexes that actually exist against the ones the latest snapshot
// records. All three are compared because all three drift the same way: a
// column missing from the snapshot mints an `ALTER TABLE … ADD`, a table
// missing from it mints a `CREATE TABLE`, exactly as a missing index mints a
// `CREATE INDEX`.
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, '..', '..', 'drizzle', 'local-sqlite');

// The indexes that legitimately appear on one side only. An exact set, not a
// floor: a floor would forbid removals while letting the next drift in.
const DOCUMENTED_ONE_SIDED_INDEXES: Record<string, string> = {
  // Migrations only. An expression index over json_extract(), which drizzle's
  // schema builder cannot express, so it is hand-written in the migration and
  // is absent from every snapshot by construction.
  idx_audit_code_change_path: 'expression index, hand-written outside the drizzle schema',
  // Migrations only, for the same reason: the activity list's turns rollup
  // reads (root_session_id, json_extract(attributes, '$.run_key')) — see 0026.
  idx_audit_session_run_key: 'expression index, hand-written outside the drizzle schema',
  // Snapshot only. 0014 dropped the legacy `events`/`findings` TABLES and put
  // compat VIEWS of the same names in their place. The drizzle schema still
  // declares them as tables, so the snapshot goes on recording their indexes,
  // but no such index exists on a real store.
  idx_events_occurred: 'index of the legacy `events` table, replaced by a view in 0014',
  idx_findings_event: 'index of the legacy `findings` table, replaced by a view in 0014',
  uq_findings_key: 'index of the legacy `findings` table, replaced by a view in 0014',
};

// The tables that legitimately appear on one side only, on the same terms.
const DOCUMENTED_ONE_SIDED_TABLES: Record<string, string> = {
  // Migrations only. Backfill scaffolding created by 0013 to track how far the
  // batched legacy copy has advanced; it is not part of the drizzle schema, so
  // no snapshot records it.
  legacy_copy_watermark: 'backfill watermark, created outside the drizzle schema',
  // Snapshot only, and the table-level half of the three index entries above:
  // 0014 replaced both tables with views of the same name while the drizzle
  // schema still declares them as tables.
  events: 'legacy table replaced by a view in 0014',
  findings: 'legacy table replaced by a view in 0014',
};

interface IndexShape {
  table: string;
  columns: (string | null)[];
  unique: boolean;
  partial: boolean;
}

interface ColumnShape {
  type: string;
  notNull: boolean;
  primaryKey: boolean;
  default: string | null;
  generated: 'virtual' | 'stored' | null;
}

type TableShape = Record<string, ColumnShape>;

function journalTags(): string[] {
  const journal = JSON.parse(
    readFileSync(join(migrationsDir, 'meta', '_journal.json'), 'utf8'),
  ) as { entries: { idx: number; tag: string }[] };
  return [...journal.entries].sort((a, b) => a.idx - b.idx).map((e) => e.tag);
}

// What a store really carries once every migration has been applied. In-memory
// rather than a temp dir: nothing here reads the store back through the
// product, so the file would only be a teardown to get wrong.
function afterMigrating(tags: string[]): {
  indexes: Map<string, IndexShape>;
  tables: Map<string, TableShape>;
} {
  const db = new DatabaseSync(':memory:');
  try {
    for (const tag of tags) {
      db.exec(readFileSync(join(migrationsDir, `${tag}.sql`), 'utf8').replace(/\r\n/g, '\n'));
    }

    const indexes = new Map<string, IndexShape>();
    // `sql IS NOT NULL` drops the implicit indexes SQLite mints for UNIQUE and
    // PRIMARY KEY constraints — no CREATE INDEX made them, so no snapshot
    // records them either.
    const indexRows = db
      .prepare("SELECT name, tbl_name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")
      .all() as unknown as { name: string; tbl_name: string }[];
    for (const { name, tbl_name: table } of indexRows) {
      const listed = db.prepare(`PRAGMA index_list(\`${table}\`)`).all() as unknown as {
        name: string;
        unique: number;
        partial: number;
      }[];
      const meta = listed.find((r) => r.name === name);
      const columns = db.prepare(`PRAGMA index_info(\`${name}\`)`).all() as unknown as {
        name: string | null;
      }[];
      indexes.set(name, {
        table,
        // NULL for an expression column, which is what makes it one.
        columns: columns.map((c) => c.name),
        unique: meta?.unique === 1,
        partial: meta?.partial === 1,
      });
    }

    const tables = new Map<string, TableShape>();
    const tableRows = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
      .all() as unknown as { name: string }[];
    for (const { name } of tableRows) {
      // table_xinfo, not table_info: table_info OMITS generated columns, and
      // eight of them are declared across audit_events and inventory. Reading
      // the narrower pragma reports those eight as snapshot-only and invites
      // documenting real columns as exceptions.
      const columns = db.prepare(`PRAGMA table_xinfo(\`${name}\`)`).all() as unknown as {
        name: string;
        type: string;
        notnull: number;
        dflt_value: string | null;
        pk: number;
        hidden: number;
      }[];
      const shape: TableShape = {};
      for (const c of columns) {
        // hidden: 0 ordinary, 1 a virtual table's hidden column, 2 GENERATED
        // ALWAYS AS … VIRTUAL, 3 … STORED. No virtual tables exist here, so a
        // 1 would be a new construct rather than something to skip silently.
        if (c.hidden === 1) throw new Error(`unexpected hidden column ${name}.${c.name}`);
        shape[c.name] = {
          // SQLite reports the declared type folded to upper case while the
          // snapshot keeps drizzle's lower-case spelling; the type itself is
          // the comparable part.
          type: c.type.toLowerCase(),
          notNull: c.notnull === 1,
          primaryKey: c.pk > 0,
          default: c.dflt_value ?? null,
          generated: c.hidden === 2 ? 'virtual' : c.hidden === 3 ? 'stored' : null,
        };
      }
      tables.set(name, shape);
    }

    return { indexes, tables };
  } finally {
    db.close();
  }
}

// What drizzle-kit believes that same chain produced.
function inLatestSnapshot(tags: string[]): {
  indexes: Map<string, IndexShape>;
  tables: Map<string, TableShape>;
} {
  const latest = tags.at(-1);
  if (latest === undefined) throw new Error('journal has no entries');
  const snapshot = JSON.parse(
    readFileSync(join(migrationsDir, 'meta', `${latest.slice(0, 4)}_snapshot.json`), 'utf8'),
  ) as {
    tables: Record<
      string,
      {
        indexes?: Record<string, { columns: string[]; isUnique?: boolean; where?: string }>;
        columns?: Record<
          string,
          {
            name?: string;
            type: string;
            notNull?: boolean;
            primaryKey?: boolean;
            default?: string | number | null;
            generated?: { as: string; type: 'virtual' | 'stored' };
          }
        >;
      }
    >;
  };

  const indexes = new Map<string, IndexShape>();
  const tables = new Map<string, TableShape>();
  for (const [table, def] of Object.entries(snapshot.tables)) {
    for (const [name, index] of Object.entries(def.indexes ?? {})) {
      indexes.set(name, {
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
    const shape: TableShape = {};
    for (const [key, column] of Object.entries(def.columns ?? {})) {
      shape[column.name ?? key] = {
        type: column.type.toLowerCase(),
        notNull: column.notNull === true,
        primaryKey: column.primaryKey === true,
        default: column.default == null ? null : String(column.default),
        // The generated expression TEXT is left out for the reason the WHERE
        // text is, plus one of its own: reading it back requires parsing
        // sqlite_master's DDL, and a parse that silently matches nothing
        // reports agreement it never checked. Whether a column is generated,
        // and virtual or stored, comes from the pragma and is compared.
        generated: column.generated ? column.generated.type : null,
      };
    }
    tables.set(table, shape);
  }
  return { indexes, tables };
}

function oneSided<T>(a: Map<string, T>, b: Map<string, T>): string[] {
  return [...new Set([...a.keys(), ...b.keys()])].filter((k) => a.has(k) !== b.has(k)).sort();
}

describe('drizzle snapshot vs. the migrations it claims to describe', () => {
  const tags = journalTags();
  const fromMigrations = afterMigrating(tags);
  const fromSnapshot = inLatestSnapshot(tags);

  const mintsADuplicate =
    'a mismatch here makes `pnpm --filter @akasecurity/schema gen:sqlite-ddl` mint a duplicate migration on every run';

  it(`records every index the migrations create, and no index they do not (${mintsADuplicate})`, () => {
    expect(oneSided(fromMigrations.indexes, fromSnapshot.indexes)).toEqual(
      Object.keys(DOCUMENTED_ONE_SIDED_INDEXES).sort(),
    );
  });

  it('agrees with the migrations on index columns, uniqueness and partiality', () => {
    for (const [name, recorded] of fromSnapshot.indexes) {
      const built = fromMigrations.indexes.get(name);
      if (!built) continue; // one-sided; pinned by the test above
      expect(built, `index ${name}`).toEqual(recorded);
    }
  });

  it(`records every table the migrations create, and no table they do not (${mintsADuplicate})`, () => {
    expect(oneSided(fromMigrations.tables, fromSnapshot.tables)).toEqual(
      Object.keys(DOCUMENTED_ONE_SIDED_TABLES).sort(),
    );
  });

  it(`agrees with the migrations on every column of every table (${mintsADuplicate})`, () => {
    for (const [name, recorded] of fromSnapshot.tables) {
      const built = fromMigrations.tables.get(name);
      if (!built) continue; // one-sided; pinned by the test above
      // The whole column map in one assertion: a missing column, an extra one
      // and a changed attribute all surface with the table named.
      expect(built, `table ${name}`).toEqual(recorded);
    }
  });
});
