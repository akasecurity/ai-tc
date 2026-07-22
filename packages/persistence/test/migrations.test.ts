import { DatabaseSync } from 'node:sqlite';

import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { columnNames, schemaObjectExists } from '../src/db/migrations/introspection.ts';
import { sourceProjectId } from '../src/ids.ts';
import {
  applyMigrations,
  reconcileSourceProjectIds,
  TOKEN_USAGE_COLUMNS,
} from '../src/migrations.ts';

// The six token-usage generated columns are defined in THREE places that must stay
// in lockstep: the canonical `0001_adorable_marten_broadcloak` migration in
// `@akasecurity/schema` (packages/schema/src/drizzle/sqlite-ddl.ts, generated from the
// drizzle defs in packages/schema/src/drizzle/local/sqlite.ts), and the
// re-hardcoded ALTER copy in `migrations.ts` (TOKEN_USAGE_COLUMNS). The copy exists
// because `@akasecurity/persistence` may not import `@akasecurity/schema`'s drizzle layer, so the
// objects can't be shared.
//
// This is the drift guard. We can't import the canonical column list cleanly
// (sqlite-ddl exposes only the whole-file migration SQL, not a structured column
// set), so the expected names are hardcoded here. If that migration adds,
// removes, or renames a token column, mirror it in BOTH places and update this list
// — the test fails loudly the moment the persistence copy drifts in count or name.
const EXPECTED_TOKEN_COLUMN_NAMES = [
  'input_tokens',
  'output_tokens',
  'cache_creation_input_tokens',
  'cache_read_input_tokens',
  'model',
  'provider',
] as const;

describe('token-usage column parity guard', () => {
  it('TOKEN_USAGE_COLUMNS names match the canonical 0010 set exactly', () => {
    const actual = TOKEN_USAGE_COLUMNS.map((c) => c.name).sort();
    const expected = [...EXPECTED_TOKEN_COLUMN_NAMES].sort();
    expect(actual).toEqual(expected);
  });
});

function appliedTags(db: DatabaseSync): string[] {
  return (db.prepare('SELECT tag FROM migration_ledger ORDER BY tag').all() as { tag: string }[])
    .map((r) => r.tag)
    .sort();
}

describe('applyMigrations tag ledger', () => {
  it('records every applied tag on a fresh store and stamps user_version for downgrade compat', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      expect(appliedTags(db)).toEqual(SQLITE_MIGRATIONS.map((m) => m.tag).sort());
      const version = (db.prepare('PRAGMA user_version').get() as { user_version: number })
        .user_version;
      expect(version).toBe(SQLITE_MIGRATIONS.length);
    } finally {
      db.close();
    }
  });

  it('reconciles a RENUMBERED history: adopts present migrations by tag, applies the missing one', () => {
    const db = new DatabaseSync(':memory:');
    try {
      // Rebuild the broken dev store: a feature branch shipped the shares/inventory
      // migration (now 0003_rich_sage) at position 2 BEFORE main landed the
      // exceptions migration as 0002_groovy_big_bertha, and the old count applier
      // stamped user_version accordingly. The count says "all but one applied" but
      // no longer says WHICH — positionally slicing replays 0003 ("table
      // egress_decision_override already exists") and never applies 0002.
      for (const migration of SQLITE_MIGRATIONS) {
        if (migration.tag === '0002_groovy_big_bertha') continue;
        db.exec(migration.sql);
      }
      db.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length - 1)}`);

      applyMigrations(db);

      // The genuinely missing migration ran; everything already present was
      // adopted into the ledger rather than replayed (a replay would throw).
      expect(schemaObjectExists(db, 'table', 'exceptions')).toBe(true);
      expect(appliedTags(db)).toEqual(SQLITE_MIGRATIONS.map((m) => m.tag).sort());

      // And the reconciled store is idempotent from here on.
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
    } finally {
      db.close();
    }
  });

  it('recreates an index a table-recreate migration drops mid-flight (0005 FK relaxation)', () => {
    const db = new DatabaseSync(':memory:');
    try {
      // Fresh replay: 0003 creates mcp_trust_override WITH uq_mcp_trust_override,
      // 0005 recreates the table (dropping that index with it) and must recreate
      // the index even though it existed when the migration STARTED. A stale
      // pre-filter here left the rebuilt table unconstrained, breaking every
      // ON CONFLICT (asset_id) upsert.
      applyMigrations(db);
      expect(schemaObjectExists(db, 'index', 'uq_mcp_trust_override')).toBe(true);

      // 0005's other half is dropping the asset_id FK: assert the recreated table
      // carries none, so this coverage doesn't hinge on enforcement state. (The
      // applier happens to leave PRAGMA foreign_keys ON after 0005's envelope, but
      // the FK-enforced end-to-end path is exercised by the #324 integration test.)
      expect(db.prepare('PRAGMA foreign_key_list(mcp_trust_override)').all()).toHaveLength(0);

      // And the constraint actually holds: the trust upsert path works.
      db.prepare(
        `INSERT INTO mcp_trust_override (id, asset_id, trust, created_at, updated_at)
         VALUES ('o1', 'asset-1', 'known-good', 0, 0)
         ON CONFLICT (asset_id) DO UPDATE SET trust = excluded.trust`,
      ).run();
    } finally {
      db.close();
    }
  });

  it('backfills the ledger for a pre-ledger count-only store without replaying anything', () => {
    const db = new DatabaseSync(':memory:');
    try {
      // A store fully migrated by the old applier: all DDL present, state only in
      // user_version, no ledger. Any replay would throw "already exists".
      for (const migration of SQLITE_MIGRATIONS) db.exec(migration.sql);
      db.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length)}`);

      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(appliedTags(db)).toEqual(SQLITE_MIGRATIONS.map((m) => m.tag).sort());
    } finally {
      db.close();
    }
  });

  it('recreates a missing index when adopting an already-applied migration', () => {
    const db = new DatabaseSync(':memory:');
    try {
      // An early-adopter shape: the 0001 token columns exist (the out-of-band
      // ensureTokenUsageColumns backfill) but its index was never created. That
      // must not read as divergence — adopt the tag and backfill the index.
      for (const migration of SQLITE_MIGRATIONS) db.exec(migration.sql);
      db.exec('DROP INDEX idx_audit_session_type');
      db.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length)}`);

      applyMigrations(db);
      expect(schemaObjectExists(db, 'index', 'idx_audit_session_type')).toBe(true);
    } finally {
      db.close();
    }
  });

  it('fails loudly when an unledgered migration is only PARTIALLY present, naming the tag', () => {
    const db = new DatabaseSync(':memory:');
    try {
      // A stray table from 0003 with the rest of that migration missing: neither
      // pending (a replay would collide) nor applied (its siblings are absent).
      // Replaying or skipping would both corrupt — the applier must refuse.
      db.exec('CREATE TABLE egress_decision_override (id text PRIMARY KEY)');
      expect(() => {
        applyMigrations(db);
      }).toThrow(/0003_rich_sage/);
    } finally {
      db.close();
    }
  });
});

describe('applyMigrations finding resolution', () => {
  it('adds findings.finding_key and creates the finding_resolution table', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);

      const findingsColumns = db.prepare('PRAGMA table_xinfo(findings)').all() as {
        name: string;
      }[];
      expect(findingsColumns.some((c) => c.name === 'finding_key')).toBe(true);

      expect(schemaObjectExists(db, 'table', 'finding_resolution')).toBe(true);
    } finally {
      db.close();
    }
  });
});

describe('source_project id reconcile', () => {
  const URL = 'https://github.com/akasecurity/ai-tc.git';
  // What the legacy derivation produced: sha256 over [randomTenantId, …] — the
  // tenant id is gone, so the reconcile can only recognize it as "not canonical".
  const LEGACY_ID = '1facd74e-tenant-era-legacy';

  // A migrated store with the same FK enforcement as openWithPragmas, so the
  // repoint-before-delete ordering is actually exercised.
  function openStore(): DatabaseSync {
    const db = new DatabaseSync(':memory:');
    db.exec('PRAGMA foreign_keys = ON');
    applyMigrations(db);
    return db;
  }

  function insertProject(
    db: DatabaseSync,
    id: string,
    firstSeen: number,
    lastSeen: number,
    name = 'ai-control-plane',
    attributes = '{}',
  ): void {
    db.prepare(
      `INSERT INTO source_project (id, url, name, attributes, first_seen, last_seen)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(id, URL, name, attributes, firstSeen, lastSeen);
  }

  function projectRows(db: DatabaseSync): { id: string; first_seen: number; last_seen: number }[] {
    return db
      .prepare('SELECT id, first_seen, last_seen FROM source_project WHERE url = ?')
      .all(URL) as { id: string; first_seen: number; last_seen: number }[];
  }

  it('folds a legacy-id duplicate into the canonical row, repointing every reference', () => {
    const db = openStore();
    try {
      insertProject(db, LEGACY_ID, 100, 200);
      insertProject(db, sourceProjectId(URL), 150, 300);

      // References under the LEGACY id across all four referencing tables.
      db.prepare(
        `INSERT INTO audit_events (id, event_type, source_project_id, started_at)
         VALUES ('evt-1', 'session', ?, 100)`,
      ).run(LEGACY_ID);
      db.prepare(
        `INSERT INTO project_file
           (id, project_id, path, name, origin, default_access, created_at, updated_at)
         VALUES ('pf-legacy-only', ?, 'src/unique.ts', 'unique.ts', 'scan', 'allowed', 100, 100)`,
      ).run(LEGACY_ID);
      // The SAME path under both ids — UNIQUE(project_id, path) makes a blind
      // repoint collide; the canonical copy must survive.
      db.prepare(
        `INSERT INTO project_file
           (id, project_id, path, name, origin, default_access, created_at, updated_at)
         VALUES ('pf-legacy-dup', ?, 'src/shared.ts', 'shared.ts', 'scan', 'allowed', 100, 100)`,
      ).run(LEGACY_ID);
      db.prepare(
        `INSERT INTO project_file
           (id, project_id, path, name, origin, default_access, created_at, updated_at)
         VALUES ('pf-canonical', ?, 'src/shared.ts', 'shared.ts', 'scan', 'allowed', 150, 150)`,
      ).run(sourceProjectId(URL));
      db.prepare(
        `INSERT INTO file_access_override (id, project_id, path, access, created_at, updated_at)
         VALUES ('fao-1', ?, '.env', 'blocked', 100, 100)`,
      ).run(LEGACY_ID);
      db.exec(
        `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
         VALUES ('dest-1', 'api', 'API', 'api.example.com', 'saas', 'trusted', 100, 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_endpoint (id, destination_id, method, transport, url, data_class, last_seen, created_at, updated_at)
         VALUES ('ep-1', 'dest-1', 'POST', 'https', 'https://api.example.com/v1', 'none', 100, 100, 100)`,
      );
      db.prepare(
        `INSERT INTO share_call_site
           (id, endpoint_id, project, file, line, snippet, project_id, created_at, updated_at)
         VALUES ('cs-1', 'ep-1', 'ai-control-plane', 'src/a.ts', 1, 'fetch()', ?, 100, 100)`,
      ).run(LEGACY_ID);

      reconcileSourceProjectIds(db);

      // One row per url, under the canonical id, observation window widened to
      // the older first_seen / newer last_seen.
      expect(projectRows(db)).toEqual([
        { id: sourceProjectId(URL), first_seen: 100, last_seen: 300 },
      ]);

      const repointed = (col: string, table: string): string[] =>
        (db.prepare(`SELECT ${col} AS v FROM ${table} ORDER BY 1`).all() as { v: string }[]).map(
          (r) => r.v,
        );
      expect(repointed('source_project_id', 'audit_events')).toEqual([sourceProjectId(URL)]);
      expect(repointed('project_id', 'file_access_override')).toEqual([sourceProjectId(URL)]);
      expect(repointed('project_id', 'share_call_site')).toEqual([sourceProjectId(URL)]);

      // The colliding path kept the canonical copy; the unique path was repointed.
      const files = db.prepare('SELECT id, project_id FROM project_file ORDER BY id').all() as {
        id: string;
        project_id: string;
      }[];
      expect(files).toEqual([
        { id: 'pf-canonical', project_id: sourceProjectId(URL) },
        { id: 'pf-legacy-only', project_id: sourceProjectId(URL) },
      ]);
    } finally {
      db.close();
    }
  });

  it('re-keys a legacy row in place when the canonical id has no row yet', () => {
    const db = openStore();
    try {
      insertProject(db, LEGACY_ID, 100, 200, 'ai-control-plane', '{"visibility":"private"}');

      reconcileSourceProjectIds(db);

      const rows = db.prepare('SELECT * FROM source_project WHERE url = ?').all(URL) as {
        id: string;
        name: string;
        attributes: string;
        first_seen: number;
        last_seen: number;
      }[];
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        id: sourceProjectId(URL),
        name: 'ai-control-plane',
        attributes: '{"visibility":"private"}',
        first_seen: 100,
        last_seen: 200,
      });
    } finally {
      db.close();
    }
  });

  it('folds several legacy rows for one url into a single canonical row, newest wins', () => {
    const db = openStore();
    try {
      // Two legacy rows for the SAME url with no canonical row yet — e.g. the
      // random tenantId was regenerated across plugin versions, so the repo hashed
      // to two distinct legacy ids. Neither equals sourceProjectId(url).
      insertProject(db, 'legacy-old', 50, 200, 'old-name', '{"v":"old"}');
      insertProject(db, 'legacy-new', 100, 400, 'new-name', '{"v":"new"}');
      // The SAME path under BOTH legacy ids: once the first row re-keys onto the
      // canonical id, the second row's repoint must hit the dedupe DELETE rather
      // than trip UNIQUE(project_id, path).
      db.prepare(
        `INSERT INTO project_file
           (id, project_id, path, name, origin, default_access, created_at, updated_at)
         VALUES ('pf-old', ?, 'src/shared.ts', 'shared.ts', 'scan', 'allowed', 50, 50)`,
      ).run('legacy-old');
      db.prepare(
        `INSERT INTO project_file
           (id, project_id, path, name, origin, default_access, created_at, updated_at)
         VALUES ('pf-new', ?, 'src/shared.ts', 'shared.ts', 'scan', 'allowed', 100, 100)`,
      ).run('legacy-new');

      reconcileSourceProjectIds(db);

      // One canonical row; window spans both sightings; name/attributes come from
      // the newest (last_seen) legacy row, deterministically — not whichever the
      // scan happened to yield first.
      const rows = db.prepare('SELECT * FROM source_project WHERE url = ?').all(URL) as {
        id: string;
        name: string;
        attributes: string;
        first_seen: number;
        last_seen: number;
      }[];
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        id: sourceProjectId(URL),
        name: 'new-name',
        attributes: '{"v":"new"}',
        first_seen: 50,
        last_seen: 400,
      });
      // Exactly one project_file survived the collision, repointed to canonical.
      const files = db.prepare('SELECT id, project_id FROM project_file ORDER BY id').all() as {
        id: string;
        project_id: string;
      }[];
      expect(files).toEqual([{ id: 'pf-new', project_id: sourceProjectId(URL) }]);
    } finally {
      db.close();
    }
  });

  it('runs from applyMigrations, is idempotent, and never re-keys sample rows', () => {
    const db = openStore();
    try {
      insertProject(db, LEGACY_ID, 100, 200);
      insertProject(db, sourceProjectId(URL), 150, 300);
      // Sample rows (legacy demo dataset / test fixtures — test-fixtures/sample-ids.ts)
      // are deliberately keyed off the content-addressed space — the url also hashes
      // elsewhere, but the row must survive untouched or the sample purge breaks.
      db.prepare(
        `INSERT INTO source_project (id, url, name, attributes, first_seen, last_seen)
         VALUES ('sample:project:checkout', 'https://github.com/acme/checkout.git', 'checkout',
                 '{"provenance":"sample"}', 50, 60)`,
      ).run();

      applyMigrations(db);
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();

      expect(projectRows(db)).toEqual([
        { id: sourceProjectId(URL), first_seen: 100, last_seen: 300 },
      ]);
      expect(db.prepare("SELECT id FROM source_project WHERE id LIKE 'sample:%'").all()).toEqual([
        { id: 'sample:project:checkout' },
      ]);
    } finally {
      db.close();
    }
  });
});

describe('applyMigrations token-usage backfill', () => {
  // PRAGMA table_xinfo (NOT table_info) — VIRTUAL generated columns are omitted from
  // table_info, so probing with it would miss these.
  function tokenColumns(db: DatabaseSync): Set<string> {
    return new Set(columnNames(db, 'audit_events', { includeGenerated: true }));
  }

  it('produces exactly the canonical token columns on a fresh store and is idempotent', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      const afterFirst = tokenColumns(db);
      for (const name of EXPECTED_TOKEN_COLUMN_NAMES) {
        expect(afterFirst.has(name)).toBe(true);
      }

      // Re-running must be a no-op (the ADD COLUMN guard probes table_xinfo). A
      // blind re-ALTER would throw "duplicate column name".
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(tokenColumns(db)).toEqual(afterFirst);
    } finally {
      db.close();
    }
  });
});

// ─── Migration 0006 (write gate) compat ──────────────────────────────────────

function splitBreakpoints(sql: string): string[] {
  return sql
    .split(/-->\s*statement-breakpoint/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// A store as an alpha.6-era binary left it: migrations 0000–0004 applied and
// tag-tracked, user_version stamped at 5.
function alpha6EraStore(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)');
  for (const migration of SQLITE_MIGRATIONS.slice(0, 5)) {
    for (const statement of splitBreakpoints(migration.sql)) db.exec(statement);
    db.prepare('INSERT INTO migration_ledger (tag, applied_at) VALUES (?, ?)').run(
      migration.tag,
      1,
    );
  }
  db.exec('PRAGMA user_version = 5');
  return db;
}

describe('migration 0006 (installed_packs write gate)', () => {
  it('applies cleanly to an alpha.6-era store: gate table seeded closed, trigger + recorded_by present', () => {
    const db = alpha6EraStore();
    try {
      applyMigrations(db);
      expect(schemaObjectExists(db, 'table', '_pack_write_gate')).toBe(true);
      expect(
        db
          .prepare(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_installed_packs_write_gate'",
          )
          .get(),
      ).toBeDefined();
      expect(db.prepare('SELECT open FROM _pack_write_gate WHERE id = 1').get()).toMatchObject({
        open: 0,
      });
      const columns = db.prepare('PRAGMA table_xinfo(available_packs)').all() as {
        name: string;
      }[];
      expect(columns.some((c) => c.name === 'recorded_by')).toBe(true);
    } finally {
      db.close();
    }
  });

  it('is idempotent: a second run against the migrated store is a no-op', () => {
    const db = alpha6EraStore();
    try {
      applyMigrations(db);
      const tags = appliedTags(db);
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(appliedTags(db)).toEqual(tags);
    } finally {
      db.close();
    }
  });

  it('self-heals the gate trigger + seed row when they are missing (adopted tag / push-built store)', () => {
    // The evidence probe sees only tables and ADDed columns, so a store owning
    // the gate TABLE + recorded_by column but not the TRIGGER (a drizzle-push
    // dev store, or any out-of-band shape) adopts the 0006 tag with the
    // security control absent. ensureWriteGateTrigger must close that hole on
    // the next open, unconditionally.
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      // Sabotage: the exact "ledger says migrated, control absent" shape.
      db.exec('DROP TRIGGER trg_installed_packs_write_gate');
      db.exec('DELETE FROM _pack_write_gate');

      applyMigrations(db);

      expect(
        db
          .prepare(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_installed_packs_write_gate'",
          )
          .get(),
      ).toBeDefined();
      expect(db.prepare('SELECT open FROM _pack_write_gate WHERE id = 1').get()).toMatchObject({
        open: 0,
      });
      // And the restored gate actually gates: a raw content UPDATE no-ops.
      db.prepare(
        `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
         VALUES ('i1', 'aka', 'secrets', '2.0.0', 'S', '[]', 1, 0, 0)`,
      ).run();
      db.exec(`UPDATE installed_packs SET version = '9.9.9' WHERE pack_id = 'secrets'`);
      expect(
        db.prepare(`SELECT version FROM installed_packs WHERE pack_id = 'secrets'`).get(),
      ).toMatchObject({ version: '2.0.0' });
    } finally {
      db.close();
    }
  });

  it('creates the gate when the 0006 tag is ADOPTED off table+column evidence (trigger never ran)', () => {
    // A review scenario end-to-end: build a store where 0006's evidence
    // objects exist out of band (no ledger row), so the applier adopts the tag
    // and filters out every non-index statement — including the CREATE TRIGGER
    // and the gate seed. The ensure* pass must still install the control.
    const db = new DatabaseSync(':memory:');
    try {
      for (const migration of SQLITE_MIGRATIONS) {
        if (migration.tag === '0006_magenta_flatman') continue;
        db.exec(migration.sql);
      }
      // Out-of-band acquisition of 0006's evidence: table + column, NO trigger.
      db.exec(`CREATE TABLE _pack_write_gate (
        id integer PRIMARY KEY NOT NULL,
        open integer DEFAULT 0 NOT NULL,
        CONSTRAINT "ck_pack_write_gate_single_row" CHECK("_pack_write_gate"."id" = 1)
      )`);
      db.exec('ALTER TABLE available_packs ADD COLUMN recorded_by text');

      applyMigrations(db);

      // Tag adopted, not replayed — and the control exists anyway.
      expect(appliedTags(db)).toContain('0006_magenta_flatman');
      expect(
        db
          .prepare(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_installed_packs_write_gate'",
          )
          .get(),
      ).toBeDefined();
      expect(db.prepare('SELECT open FROM _pack_write_gate WHERE id = 1').get()).toMatchObject({
        open: 0,
      });
    } finally {
      db.close();
    }
  });

  it('a legacy position-count runner (≤alpha.5) no-ops against a store already past its horizon', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db); // fully migrated: user_version = SQLITE_MIGRATIONS.length
      const current = (db.prepare('PRAGMA user_version').get() as { user_version: number })
        .user_version;
      expect(current).toBe(SQLITE_MIGRATIONS.length);

      // Replicate the pre-09ceccc applier verbatim (git history of this file):
      // it sliced its OWN compiled-in migration list — five entries in an
      // alpha.5 binary — from the stored count. With the count past its list
      // length the slice is empty and the version stamp is skipped: a clean
      // no-op, never a throw, never a downgrade of user_version.
      const legacyKnown = SQLITE_MIGRATIONS.slice(0, 5);
      expect(() => {
        for (const migration of legacyKnown.slice(current)) {
          db.exec(migration.sql);
        }
        if (current < legacyKnown.length) {
          db.exec(`PRAGMA user_version = ${String(legacyKnown.length)}`);
        }
      }).not.toThrow();
      expect(
        (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version,
      ).toBe(SQLITE_MIGRATIONS.length);
    } finally {
      db.close();
    }
  });
});
