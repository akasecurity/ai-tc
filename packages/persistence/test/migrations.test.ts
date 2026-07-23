import { DatabaseSync } from 'node:sqlite';

import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { columnNames, schemaObjectExists } from '../src/db/migrations/introspection.ts';
import { inspectionDefinitionId, sourceProjectId } from '../src/ids.ts';
import {
  applyMigrations,
  LEGACY_BACKFILL_BATCH_SIZE,
  LEGACY_BACKFILL_MAX_ROWS_PER_CALL,
  reconcileSourceProjectIds,
  runLegacyHistoryBackfill,
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

describe('applyMigrations inspection_findings identity columns (0011)', () => {
  // The FK parents inspection_findings requires: one audit_events row, one
  // inspection_definitions row.
  function seedInspectionFindingParents(
    db: DatabaseSync,
    eventId: string,
    definitionId: string,
  ): void {
    db.prepare(
      `INSERT INTO audit_events (id, event_type, started_at) VALUES (?, 'tool_call', 0)`,
    ).run(eventId);
    db.prepare(
      `INSERT INTO inspection_definitions
         (id, rule_id, name, category, severity, definition, version)
       VALUES (?, 'aws-key', 'AWS Key', 'secret', 'critical', '{}', '1')`,
    ).run(definitionId);
  }

  function insertFinding(
    db: DatabaseSync,
    id: string,
    eventId: string,
    definitionId: string,
    findingKey: string | null,
  ): void {
    db.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, span_start, span_end,
          masked_match, action_taken, confidence, finding_key)
       VALUES (?, ?, ?, 0, 1, '••', 'log', 1, ?)`,
    ).run(id, eventId, definitionId, findingKey);
  }

  it('prepares an ON CONFLICT (finding_key) upsert against inspection_findings', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);

      // Preparation only — nothing writes finding_key yet, so this must not
      // run. A partial index would make this exact statement fail to prepare
      // ("ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE
      // constraint"), so successful preparation alone pins the full-index shape.
      expect(() => {
        db.prepare(
          `INSERT INTO inspection_findings
             (id, audit_event_id, inspection_definition_id, span_start, span_end,
              masked_match, action_taken, confidence, finding_key)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (finding_key) DO UPDATE SET masked_match = excluded.masked_match`,
        );
      }).not.toThrow();
    } finally {
      db.close();
    }
  });

  it('lets two key-less inspection_findings rows coexist under the unique index', () => {
    const db = new DatabaseSync(':memory:');
    db.exec('PRAGMA foreign_keys = ON');
    try {
      applyMigrations(db);
      seedInspectionFindingParents(db, 'evt-1', 'def-1');

      expect(() => {
        insertFinding(db, 'f1', 'evt-1', 'def-1', null);
        insertFinding(db, 'f2', 'evt-1', 'def-1', null);
      }).not.toThrow();

      const rows = db
        .prepare('SELECT id FROM inspection_findings WHERE finding_key IS NULL ORDER BY id')
        .all() as { id: string }[];
      expect(rows).toEqual([{ id: 'f1' }, { id: 'f2' }]);
    } finally {
      db.close();
    }
  });

  it('adopts the 0011 tag when its columns and unique index already exist out of band', () => {
    const migration011 = SQLITE_MIGRATIONS.find((m) => m.tag === '0012_handy_the_captain');
    if (migration011 === undefined) throw new Error('0012_handy_the_captain migration not found');

    const db = new DatabaseSync(':memory:');
    try {
      for (const migration of SQLITE_MIGRATIONS) {
        if (migration.tag === '0012_handy_the_captain') continue;
        db.exec(migration.sql);
      }
      // Out-of-band acquisition of 0011's evidence: the exact DDL it would run,
      // applied directly rather than through the ledger (e.g. a drizzle-push
      // dev store).
      db.exec(migration011.sql);

      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(appliedTags(db)).toContain('0012_handy_the_captain');
    } finally {
      db.close();
    }
  });

  it('executes 0011 when its columns and index are absent', () => {
    const db = new DatabaseSync(':memory:');
    try {
      for (const migration of SQLITE_MIGRATIONS) {
        if (migration.tag === '0012_handy_the_captain') continue;
        db.exec(migration.sql);
      }

      applyMigrations(db);

      expect(appliedTags(db)).toContain('0012_handy_the_captain');
      expect(columnNames(db, 'inspection_findings')).toEqual(
        expect.arrayContaining(['finding_key', 'first_detected_at']),
      );
      expect(schemaObjectExists(db, 'index', 'uq_inspection_findings_key')).toBe(true);
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

// ─── Migration 0011 (egress writer) ──────────────────────────────────────────

const EGRESS_WRITER_TAG = '0011_egress_writer';

// The columns an index covers, in index order.
function indexColumns(db: DatabaseSync, index: string): string[] {
  // PRAGMA can't be parameterized; the name comes from our own DDL constants.
  return (db.prepare(`PRAGMA index_info(${index})`).all() as { name: string }[]).map((c) => c.name);
}

// The NOT NULL flag of one column, as table_xinfo reports it.
function columnNotNull(db: DatabaseSync, table: string, column: string): number | undefined {
  return (
    db.prepare(`PRAGMA table_xinfo(${table})`).all() as { name: string; notnull: number }[]
  ).find((c) => c.name === column)?.notnull;
}

// The ON DELETE action of the outbound foreign key on `column`.
function foreignKeyOnDelete(db: DatabaseSync, table: string, column: string): string | undefined {
  return (
    db.prepare(`PRAGMA foreign_key_list(${table})`).all() as { from: string; on_delete: string }[]
  ).find((fk) => fk.from === column)?.on_delete;
}

// One destination + one override row on it, written the way an already-shipped
// binary does (destination_id only, no host).
function seedOverride(db: DatabaseSync, destId: string, host: string): void {
  db.prepare(
    `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
     VALUES (?, 'provider', 'API', ?, 'saas', 'recognized', 100, 100, 100)`,
  ).run(destId, host);
  db.prepare(
    `INSERT INTO egress_decision_override (id, destination_id, decision, created_at, updated_at)
     VALUES (?, ?, 'block', 100, 100)`,
  ).run(`ov-${destId}`, destId);
}

// A store as a pre-0011 binary left it: every earlier migration applied and
// tag-tracked, user_version stamped at that count, 0011 genuinely pending.
function preEgressWriterStore(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('CREATE TABLE migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)');
  const earlier = SQLITE_MIGRATIONS.filter((m) => m.tag !== EGRESS_WRITER_TAG);
  for (const migration of earlier) {
    for (const statement of splitBreakpoints(migration.sql)) db.exec(statement);
    db.prepare('INSERT INTO migration_ledger (tag, applied_at) VALUES (?, ?)').run(
      migration.tag,
      1,
    );
  }
  db.exec(`PRAGMA user_version = ${String(earlier.length)}`);
  return db;
}

describe('migration 0011 (egress writer schema)', () => {
  it('a fresh store carries project_key, host, and the re-keyed call-site index', () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);

      // table_xinfo, not table_info — the probe the applier itself uses.
      expect(columnNames(db, 'share_call_site', { includeGenerated: true })).toContain(
        'project_key',
      );
      expect(columnNames(db, 'egress_decision_override', { includeGenerated: true })).toContain(
        'host',
      );

      // The unique call-site key is now project_key-scoped, not display-name-scoped.
      expect(schemaObjectExists(db, 'index', 'uq_share_call_site')).toBe(true);
      expect(indexColumns(db, 'uq_share_call_site')).toEqual([
        'endpoint_id',
        'project_key',
        'file',
        'line',
      ]);

      // Per-project reconcile/confirm/totals filter on project_key alone, which
      // the endpoint_id-leading unique index cannot seek on.
      expect(schemaObjectExists(db, 'index', 'idx_share_call_site_project')).toBe(true);
      expect(indexColumns(db, 'idx_share_call_site_project')).toEqual([
        'project_key',
        'endpoint_id',
      ]);

      // The host-keyed override index is additive; the legacy destination-keyed
      // unique index that already-shipped binaries write against SURVIVES.
      expect(schemaObjectExists(db, 'index', 'uq_egress_decision_override_host')).toBe(true);
      expect(schemaObjectExists(db, 'index', 'uq_egress_decision_override')).toBe(true);

      expect(appliedTags(db)).toContain(EGRESS_WRITER_TAG);
    } finally {
      db.close();
    }
  });

  it('makes destination_id nullable with ON DELETE SET NULL so overrides outlive a prune', () => {
    // The pair that makes host-keyed survival possible at all: a NOT NULL
    // destination_id under a NO ACTION foreign key would make deleting a pruned
    // destination raise FOREIGN KEY constraint failed instead.
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      expect(columnNotNull(db, 'egress_decision_override', 'destination_id')).toBe(0);
      expect(foreignKeyOnDelete(db, 'egress_decision_override', 'destination_id')).toBe('SET NULL');

      db.exec('PRAGMA foreign_keys = ON');
      seedOverride(db, 'dest-1', 'api.example.com');
      db.prepare('UPDATE egress_decision_override SET host = ? WHERE id = ?').run(
        'api.example.com',
        'ov-dest-1',
      );

      expect(() => {
        db.prepare('DELETE FROM share_destination WHERE id = ?').run('dest-1');
      }).not.toThrow();
      expect(
        db.prepare('SELECT destination_id, host, decision FROM egress_decision_override').all(),
      ).toEqual([{ destination_id: null, host: 'api.example.com', decision: 'block' }]);
    } finally {
      db.close();
    }
  });

  it('orphaned rows stay distinct under uq_egress_decision_override, one per host', () => {
    // SQLite treats NULLs as distinct in a unique index, so any number of
    // survived rows coexist on the destination-keyed index. The host-keyed
    // index is partial on host IS NOT NULL, so one-decision-per-host still
    // holds across them.
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      db.exec('PRAGMA foreign_keys = ON');
      for (const n of ['1', '2']) {
        seedOverride(db, `dest-${n}`, `h${n}.example.com`);
        db.prepare('UPDATE egress_decision_override SET host = ? WHERE id = ?').run(
          `h${n}.example.com`,
          `ov-dest-${n}`,
        );
      }
      db.exec('DELETE FROM share_destination');

      expect(
        db
          .prepare(
            'SELECT count(*) AS n FROM egress_decision_override WHERE destination_id IS NULL',
          )
          .get(),
      ).toEqual({ n: 2 });
      // …but the two orphans still cannot claim the same host.
      expect(() => {
        db.prepare('UPDATE egress_decision_override SET host = ? WHERE id = ?').run(
          'h1.example.com',
          'ov-dest-2',
        );
      }).toThrow(/UNIQUE/i);
    } finally {
      db.close();
    }
  });

  it("project_key is NOT NULL DEFAULT '' so the ALTER is legal on existing rows", () => {
    const db = new DatabaseSync(':memory:');
    try {
      applyMigrations(db);
      const column = (
        db.prepare('PRAGMA table_xinfo(share_call_site)').all() as {
          name: string;
          notnull: number;
          dflt_value: string | null;
        }[]
      ).find((c) => c.name === 'project_key');
      expect(column?.notnull).toBe(1);
      expect(column?.dflt_value).toBe("''");
    } finally {
      db.close();
    }
  });

  it('upgrades a pre-0011 store in place, preserving its existing call sites', () => {
    const db = preEgressWriterStore();
    try {
      // A row written by the pre-0011 binary, under the old 4-column key.
      db.exec(
        `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
         VALUES ('dest-1', 'provider', 'API', 'api.example.com', 'saas', 'recognized', 100, 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_endpoint (id, destination_id, method, transport, url, data_class, last_seen, created_at, updated_at)
         VALUES ('ep-1', 'dest-1', 'POST', 'https', 'https://api.example.com/v1', 'none', 100, 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_call_site (id, endpoint_id, project, file, line, snippet, created_at, updated_at)
         VALUES ('cs-1', 'ep-1', 'payments-api', 'src/a.ts', 1, 'fetch()', 100, 100)`,
      );
      // …and an override on it, in the pre-0011 shape (no host column yet).
      db.exec(
        `INSERT INTO egress_decision_override (id, destination_id, decision, created_at, updated_at)
         VALUES ('ov-1', 'dest-1', 'block', 100, 100)`,
      );

      applyMigrations(db);

      expect(appliedTags(db)).toEqual(SQLITE_MIGRATIONS.map((m) => m.tag).sort());
      // The pre-existing row survives, backfilled from the old key's project.
      expect(
        db.prepare('SELECT project_key FROM share_call_site WHERE id = ?').get('cs-1'),
      ).toEqual({ project_key: 'legacy:payments-api' });
      expect(indexColumns(db, 'uq_share_call_site')).toEqual([
        'endpoint_id',
        'project_key',
        'file',
        'line',
      ]);
      // The project-key index is created on an upgraded store too, not only a fresh one.
      expect(indexColumns(db, 'idx_share_call_site_project')).toEqual([
        'project_key',
        'endpoint_id',
      ]);

      // The override table is REBUILT (nullable destination_id, ON DELETE SET
      // NULL) and its rows are copied across, host-NULL like the writer left them.
      expect(
        db.prepare('SELECT destination_id, host, decision FROM egress_decision_override').all(),
      ).toEqual([{ destination_id: 'dest-1', host: null, decision: 'block' }]);
      expect(columnNotNull(db, 'egress_decision_override', 'destination_id')).toBe(0);
      expect(foreignKeyOnDelete(db, 'egress_decision_override', 'destination_id')).toBe('SET NULL');
      // The rebuild drops the old table's indexes with it; both are back.
      expect(indexColumns(db, 'uq_egress_decision_override')).toEqual(['destination_id']);
      expect(schemaObjectExists(db, 'index', 'uq_egress_decision_override_host')).toBe(true);

      // And the upgraded store is idempotent from here on.
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
    } finally {
      db.close();
    }
  });

  it('upgrades a pre-0011 store whose call sites differ only by project', () => {
    // The old key was (endpoint_id, project, file, line), so the same file/line
    // hitting the same endpoint from two projects was legal. Backfilling both to
    // one project_key would collide on the new index, abort the migration inside
    // BEGIN IMMEDIATE, and — on the plugin hook path, where the throw is
    // swallowed fail-open — stop capture on every later open.
    const db = preEgressWriterStore();
    try {
      db.exec(
        `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
         VALUES ('dest-1', 'provider', 'API', 'api.example.com', 'saas', 'recognized', 100, 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_endpoint (id, destination_id, method, transport, url, data_class, last_seen, created_at, updated_at)
         VALUES ('ep-1', 'dest-1', 'POST', 'https', 'https://api.example.com/v1', 'none', 100, 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_call_site (id, endpoint_id, project, file, line, snippet, created_at, updated_at)
         VALUES ('cs-1', 'ep-1', 'payments-api', 'src/a.ts', 1, 'fetch()', 100, 100)`,
      );
      db.exec(
        `INSERT INTO share_call_site (id, endpoint_id, project, file, line, snippet, created_at, updated_at)
         VALUES ('cs-2', 'ep-1', 'crm-sync', 'src/a.ts', 1, 'fetch()', 100, 100)`,
      );

      expect(() => {
        applyMigrations(db);
      }).not.toThrow();

      // Both rows survive on distinct keys — the re-key never drops a project.
      expect(db.prepare('SELECT id, project_key FROM share_call_site ORDER BY id').all()).toEqual([
        { id: 'cs-1', project_key: 'legacy:payments-api' },
        { id: 'cs-2', project_key: 'legacy:crm-sync' },
      ]);
      expect(appliedTags(db)).toEqual(SQLITE_MIGRATIONS.map((m) => m.tag).sort());
    } finally {
      db.close();
    }
  });

  it('survives a pending store whose uq_share_call_site was dropped out of band', () => {
    // The exact shape `DROP INDEX IF EXISTS` exists to absorb: 0011 is genuinely
    // pending (neither new column present), so its non-index statements all run —
    // but the index the DROP targets is already gone. A bare DROP INDEX throws
    // here, and on the plugin hook path that throw is swallowed fail-open, so
    // capture would silently stop.
    const db = preEgressWriterStore();
    try {
      db.exec('DROP INDEX uq_share_call_site');
      expect(schemaObjectExists(db, 'index', 'uq_share_call_site')).toBe(false);

      expect(() => {
        applyMigrations(db);
      }).not.toThrow();

      expect(indexColumns(db, 'uq_share_call_site')).toEqual([
        'endpoint_id',
        'project_key',
        'file',
        'line',
      ]);
      expect(appliedTags(db)).toContain(EGRESS_WRITER_TAG);
    } finally {
      db.close();
    }
  });

  // Already-shipped binaries write egress_decision_override with this exact
  // statement shape and no `host`. Their ON CONFLICT target is the
  // destination-keyed unique index, which the rebuild recreates — so the upsert
  // must keep working against the now-nullable column, on a fresh store and on
  // one the rebuild upgraded in place alike.
  const LEGACY_UPSERT = `INSERT INTO egress_decision_override (id, destination_id, decision, created_at, updated_at)
     VALUES (?, 'dest-1', ?, 100, 100)
     ON CONFLICT (destination_id) DO UPDATE SET
       decision = excluded.decision,
       updated_at = excluded.updated_at`;

  it.each([
    ['a fresh store', () => new DatabaseSync(':memory:')],
    ['a store upgraded in place', preEgressWriterStore],
  ])('keeps the legacy ON CONFLICT (destination_id) override upsert working on %s', (_, open) => {
    const db = open();
    try {
      db.exec('PRAGMA foreign_keys = ON');
      applyMigrations(db);
      db.exec(
        `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
         VALUES ('dest-1', 'provider', 'API', 'api.example.com', 'saas', 'recognized', 100, 100, 100)`,
      );

      db.prepare(LEGACY_UPSERT).run('ov-1', 'block');
      db.prepare(LEGACY_UPSERT).run('ov-2', 'allow');

      expect(db.prepare('SELECT id, decision, host FROM egress_decision_override').all()).toEqual([
        { id: 'ov-1', decision: 'allow', host: null },
      ]);
    } finally {
      db.close();
    }
  });

  it('the host index is PARTIAL so several legacy host-NULL rows coexist', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('PRAGMA foreign_keys = ON');
      applyMigrations(db);
      for (const id of ['dest-1', 'dest-2']) {
        db.prepare(
          `INSERT INTO share_destination (id, kind, name, host, category, trust, last_seen, created_at, updated_at)
           VALUES (?, 'provider', 'API', ?, 'saas', 'recognized', 100, 100, 100)`,
        ).run(id, `${id}.example.com`);
        db.prepare(
          `INSERT INTO egress_decision_override (id, destination_id, decision, created_at, updated_at)
           VALUES (?, ?, 'block', 100, 100)`,
        ).run(`ov-${id}`, id);
      }
      // Two host-NULL rows are fine; a duplicate non-null host is not.
      expect(
        (db.prepare('SELECT count(*) AS n FROM egress_decision_override').get() as { n: number }).n,
      ).toBe(2);
      db.prepare('UPDATE egress_decision_override SET host = ? WHERE id = ?').run(
        'api.example.com',
        'ov-dest-1',
      );
      expect(() => {
        db.prepare('UPDATE egress_decision_override SET host = ? WHERE id = ?').run(
          'api.example.com',
          'ov-dest-2',
        );
      }).toThrow(/UNIQUE/i);
    } finally {
      db.close();
    }
  });
});

// ─── Migration 0013 + the legacy history backfill ───────────────────────────

const MIGRATION_0013_TAG = '0013_legacy_history_backfill_support';

// A store on the previous binary version: every migration through 0012
// applied, 0013 (and the legacy history it would drain) still pending.
function preBackfillStore(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  for (const migration of SQLITE_MIGRATIONS) {
    if (migration.tag === MIGRATION_0013_TAG) continue;
    db.exec(migration.sql);
  }
  return db;
}

function insertLegacyEvent(
  db: DatabaseSync,
  id: string,
  occurredAt: number,
  metadata: Record<string, unknown> | null,
  overrides: { sourceTool?: string; kind?: string; content?: string } = {},
): void {
  db.prepare(
    `INSERT INTO events (id, source_tool, kind, occurred_at, content_hash, content, metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    overrides.sourceTool ?? 'claude-code',
    overrides.kind ?? 'prompt',
    occurredAt,
    `hash-${id}`,
    overrides.content ?? `content for ${id}`,
    metadata === null ? null : JSON.stringify(metadata),
  );
}

function insertLegacyFinding(
  db: DatabaseSync,
  id: string,
  eventId: string,
  overrides: {
    ruleId?: string;
    category?: string;
    severity?: string;
    findingKey?: string | null;
    firstDetectedAt?: number | null;
  } = {},
): void {
  db.prepare(
    `INSERT INTO findings
       (id, event_id, rule_id, category, severity, span_start, span_end,
        masked_match, action_taken, confidence, finding_key, first_detected_at)
     VALUES (?, ?, ?, ?, ?, 0, 10, 'AKIA…MPLE', 'redact', 0.9, ?, ?)`,
  ).run(
    id,
    eventId,
    overrides.ruleId ?? 'secrets/aws-access-key',
    overrides.category ?? 'secret',
    overrides.severity ?? 'critical',
    overrides.findingKey ?? null,
    overrides.firstDetectedAt ?? null,
  );
}

describe('migration 0013 + legacy history backfill', () => {
  it('adds the watermark table and the audit_events replacement indexes', () => {
    const db = preBackfillStore();
    try {
      applyMigrations(db);
      expect(schemaObjectExists(db, 'table', 'legacy_copy_watermark')).toBe(true);
      expect(schemaObjectExists(db, 'index', 'idx_audit_type_t')).toBe(true);
      expect(schemaObjectExists(db, 'index', 'idx_audit_code_change_path')).toBe(true);
    } finally {
      db.close();
    }
  });

  it('0013 stub-root synthesis skips a legacy event with malformed metadata', () => {
    const db = preBackfillStore();
    try {
      // A pre-validation build could have written non-JSON into events.metadata.
      // 0013's stub-root synthesis runs json_extract over EVERY legacy row, and
      // json_extract throws a hard "malformed JSON" on invalid text — which would
      // roll back and permanently wedge the migration (applyMigrations is
      // unwrapped in openLocalDatabase). The `json_valid(metadata)` guard skips
      // such rows, matching copyLegacyEvents' parseLegacyEventMetadata try/catch.
      //
      // Reachability note: the 0010 partial index on events.metadata rejects
      // malformed metadata strictly earlier (at insert, build, AND applyMigrations
      // index-backfill time — all verified), so this is only reachable under the
      // "0010 tag ledgered but the index physically absent" divergence. Model
      // exactly that by dropping the index, then run 0013's DDL directly (going
      // through applyMigrations would rebuild the 0010 index and throw first).
      db.exec('DROP INDEX idx_events_session_id');
      db.prepare(
        `INSERT INTO events (id, source_tool, kind, occurred_at, content_hash, content, metadata)
         VALUES ('ev-bad-meta', 'claude-code', 'prompt', 4000, 'h', 'c', 'not-json{')`,
      ).run();
      insertLegacyEvent(db, 'ev-good', 1000, { sessionId: 'sess-good' });

      const migration = SQLITE_MIGRATIONS.find((m) => m.tag === MIGRATION_0013_TAG);
      if (migration === undefined) throw new Error('0013 migration not found');

      expect(() => {
        db.exec(migration.sql);
      }).not.toThrow();

      // The valid session got its stub root; the malformed row was skipped, not fatal.
      expect(
        db.prepare('SELECT event_type FROM audit_events WHERE id = ?').get('sess-good'),
      ).toMatchObject({ event_type: 'session' });
      expect(
        db.prepare('SELECT id FROM audit_events WHERE id = ?').get('ev-bad-meta'),
      ).toBeUndefined();

      // The JS row-copy still drains the malformed-metadata event (its own
      // parseLegacyEventMetadata try/catch treats it as session-less), so no
      // history is lost — it lands with a NULL root.
      runLegacyHistoryBackfill(db);
      expect(
        db.prepare('SELECT root_session_id FROM audit_events WHERE id = ?').get('ev-bad-meta'),
      ).toMatchObject({ root_session_id: null });
    } finally {
      db.close();
    }
  });

  it('drains a legacy event whose session root was never stubbed (post-0013 skew) without wedging', () => {
    const db = preBackfillStore();
    try {
      // 0013 runs (nothing to stub) and is ledgered; the store is fully drained.
      applyMigrations(db);

      // Version skew: a pre-cutover binary writes NEW-session events rows AFTER
      // 0013 (ledgered, never re-run) and before the drop. sess-skew therefore
      // has no audit_events root — an FK the copy must satisfy on demand, or
      // INSERT OR IGNORE (which does NOT suppress an FK violation) throws, rolls
      // back the batch + its watermark, and wedges the drain forever.
      insertLegacyEvent(db, 'ev-skew', 9000, { sessionId: 'sess-skew' }, { kind: 'code_change' });
      insertLegacyEvent(db, 'ev-skew-2', 9500, { sessionId: 'sess-skew' }, { kind: 'code_change' });
      expect(
        db.prepare("SELECT id FROM audit_events WHERE id = 'sess-skew'").get(),
      ).toBeUndefined();

      expect(() => {
        runLegacyHistoryBackfill(db);
      }).not.toThrow();

      // The stub root was minted on demand, the poison row drained, and progress
      // continued past it.
      expect(
        db
          .prepare("SELECT event_type, root_session_id FROM audit_events WHERE id='sess-skew'")
          .get(),
      ).toMatchObject({ event_type: 'session', root_session_id: null });
      expect(
        db.prepare("SELECT root_session_id, parent_id FROM audit_events WHERE id='ev-skew'").get(),
      ).toMatchObject({ root_session_id: 'sess-skew', parent_id: 'sess-skew' });
      expect(
        (
          db
            .prepare("SELECT count(*) AS n FROM audit_events WHERE id IN ('ev-skew','ev-skew-2')")
            .get() as {
            n: number;
          }
        ).n,
      ).toBe(2);
      // The watermark advanced to the end — proof the drain is not wedged.
      const wm = (
        db
          .prepare("SELECT last_rowid AS r FROM legacy_copy_watermark WHERE source='events'")
          .get() as {
          r: number;
        }
      ).r;
      const maxRow = (db.prepare('SELECT max(rowid) AS r FROM events').get() as { r: number }).r;
      expect(wm).toBe(maxRow);
    } finally {
      db.close();
    }
  });

  it(
    'migrates rows current code can no longer produce: an orphan session, NULL metadata, ' +
      'a NULL finding_key/first_detected_at row, and a finding_key collision with a ' +
      'post-cutover live row — without ever touching the legacy tables',
    () => {
      const db = preBackfillStore();
      try {
        // A session-scoped event whose session root never made it into
        // audit_events — current code always stubs the root first (see
        // recordCapture), but a store from before that safeguard can hold one.
        insertLegacyEvent(db, 'ev-orphan-1', 1_000, { sessionId: 'sess-orphan' }, {});
        insertLegacyEvent(
          db,
          'ev-orphan-2',
          2_000,
          { sessionId: 'sess-orphan', filePath: 'src/a.ts' },
          { kind: 'code_change' },
        );
        // A NULL-metadata event: no session, no attributes beyond source_tool.
        insertLegacyEvent(db, 'ev-no-meta', 3_000, null, { sourceTool: 'cli' });

        // Pre-finding_key-era row: both nullable columns genuinely NULL.
        insertLegacyFinding(db, 'f-ancient', 'ev-orphan-1', {
          findingKey: null,
          firstDetectedAt: null,
        });

        // A legacy row whose finding_key ALREADY has a row in
        // inspection_findings from a post-cutover live capture — the exact
        // reconciliation the upsert exists for.
        insertLegacyFinding(db, 'f-legacy-key', 'ev-no-meta', {
          ruleId: 'secrets/generic-token',
          category: 'secret',
          severity: 'high',
          findingKey: 'shared-key-1',
          firstDetectedAt: 500,
        });
        db.exec(
          `INSERT INTO audit_events (id, event_type, started_at) VALUES ('live-evt', 'tool_call', 900)`,
        );
        db.exec(
          `INSERT INTO inspection_definitions
             (id, rule_id, name, category, severity, definition, version)
           VALUES ('live-def', 'secrets/generic-token', 'Generic token', 'secret', 'high', '{}', '1')`,
        );
        db.prepare(
          `INSERT INTO inspection_findings
             (id, audit_event_id, inspection_definition_id, span_start, span_end,
              masked_match, action_taken, confidence, finding_key, first_detected_at)
           VALUES ('live-finding', 'live-evt', 'live-def', 5, 20, 'TOKEN…', 'warn', 0.8, ?, 2000)`,
        ).run('shared-key-1');

        const legacyEventCountBefore = (
          db.prepare('SELECT count(*) AS n FROM events').get() as { n: number }
        ).n;
        const legacyFindingCountBefore = (
          db.prepare('SELECT count(*) AS n FROM findings').get() as { n: number }
        ).n;

        applyMigrations(db);

        // Constraint 1: the legacy tables are untouched — this is a copy, not a move.
        expect((db.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(
          legacyEventCountBefore,
        );
        expect((db.prepare('SELECT count(*) AS n FROM findings').get() as { n: number }).n).toBe(
          legacyFindingCountBefore,
        );

        // The orphan session got a synthesized root, timed at the earliest
        // event recorded under it — BEFORE either event was copied (the FK
        // that copy needs already resolves).
        expect(
          db
            .prepare(
              'SELECT event_type, root_session_id, started_at FROM audit_events WHERE id = ?',
            )
            .get('sess-orphan'),
        ).toMatchObject({ event_type: 'session', root_session_id: null, started_at: 1_000 });

        const orphanEvent = db
          .prepare('SELECT root_session_id, parent_id, attributes FROM audit_events WHERE id = ?')
          .get('ev-orphan-2') as { root_session_id: string; parent_id: string; attributes: string };
        expect(orphanEvent.root_session_id).toBe('sess-orphan');
        expect(orphanEvent.parent_id).toBe('sess-orphan');
        expect(JSON.parse(orphanEvent.attributes)).toMatchObject({
          source_tool: 'claude-code',
          file_path: 'src/a.ts',
        });

        const noMetaEvent = db
          .prepare('SELECT root_session_id, parent_id, attributes FROM audit_events WHERE id = ?')
          .get('ev-no-meta') as {
          root_session_id: string | null;
          parent_id: string | null;
          attributes: string;
        };
        expect(noMetaEvent.root_session_id).toBeNull();
        expect(noMetaEvent.parent_id).toBeNull();
        expect(JSON.parse(noMetaEvent.attributes)).toMatchObject({ source_tool: 'cli' });

        // The ancient NULL-key/NULL-first_detected_at row copied verbatim,
        // resolved onto a synthesized "unmigrated" definition whose id matches
        // a fresh, independent call to inspectionDefinitionId for the same
        // (rule_id, category, severity) tuple — the empirical id-parity check.
        const ancient = db
          .prepare(
            `SELECT f.finding_key AS findingKey, f.first_detected_at AS firstDetectedAt,
                    f.inspection_definition_id AS definitionId,
                    d.rule_id AS ruleId, d.name, d.category, d.severity, d.definition, d.version
             FROM inspection_findings f JOIN inspection_definitions d ON d.id = f.inspection_definition_id
             WHERE f.id = 'f-ancient'`,
          )
          .get() as {
          findingKey: string | null;
          firstDetectedAt: number | null;
          definitionId: string;
          ruleId: string;
          name: string;
          category: string;
          severity: string;
          definition: string;
          version: string;
        };
        expect(ancient.findingKey).toBeNull();
        expect(ancient.firstDetectedAt).toBeNull();
        expect(ancient).toMatchObject({
          ruleId: 'secrets/aws-access-key',
          name: 'secrets/aws-access-key',
          category: 'secret',
          severity: 'critical',
          definition: '',
          version: 'unmigrated/secret/critical',
        });
        expect(ancient.definitionId).toBe(
          inspectionDefinitionId('secrets/aws-access-key', 'unmigrated/secret/critical'),
        );

        // The finding_key collision: exactly one surviving row, under the
        // LIVE row's id (the legacy row's OTHER columns never overwrite it),
        // with first_detected_at reconciled down to the earlier of the two.
        const findingRows = db
          .prepare(
            `SELECT id, finding_key AS findingKey, first_detected_at AS firstDetectedAt,
                    audit_event_id AS auditEventId
             FROM inspection_findings ORDER BY id`,
          )
          .all() as {
          id: string;
          findingKey: string | null;
          firstDetectedAt: number | null;
          auditEventId: string;
        }[];
        expect(findingRows.map((r) => r.id)).toEqual(['f-ancient', 'live-finding']);
        const merged = findingRows.find((r) => r.findingKey === 'shared-key-1');
        expect(merged).toMatchObject({
          id: 'live-finding',
          firstDetectedAt: 500,
          auditEventId: 'live-evt',
        });

        // Distinct finding_key count preserved: one real key (shared-key-1);
        // NULLs never count as a key.
        expect(
          (
            db
              .prepare(
                'SELECT count(DISTINCT finding_key) AS n FROM inspection_findings WHERE finding_key IS NOT NULL',
              )
              .get() as { n: number }
          ).n,
        ).toBe(1);

        // Both legacy tables fully drained: the watermark sits at each
        // table's last rowid.
        const eventsMaxRowid = (
          db.prepare('SELECT max(rowid) AS r FROM events').get() as { r: number }
        ).r;
        const findingsMaxRowid = (
          db.prepare('SELECT max(rowid) AS r FROM findings').get() as { r: number }
        ).r;
        expect(
          db
            .prepare("SELECT last_rowid AS r FROM legacy_copy_watermark WHERE source = 'events'")
            .get(),
        ).toMatchObject({ r: eventsMaxRowid });
        expect(
          db
            .prepare("SELECT last_rowid AS r FROM legacy_copy_watermark WHERE source = 'findings'")
            .get(),
        ).toMatchObject({ r: findingsMaxRowid });

        // Re-running is a no-op: same row counts, same watermark, no throw.
        expect(() => {
          applyMigrations(db);
        }).not.toThrow();
        expect(
          (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
        ).toBe(2);
      } finally {
        db.close();
      }
    },
  );

  it('never starts the findings copy until the events copy has fully caught up', () => {
    // More events than one call's budget, so the events copy itself needs two
    // opens — and findings referencing the LAST (not-yet-copied) events, so
    // if the findings copy ran anyway on the first call, it would either
    // throw on the audit_events FK (swallowed, but making zero progress
    // forever) or — were the FK not enforced — insert a dangling reference.
    const db = preBackfillStore();
    try {
      const totalEvents = LEGACY_BACKFILL_MAX_ROWS_PER_CALL + 50;
      for (let i = 0; i < totalEvents; i += 1) {
        insertLegacyEvent(db, `ev-${String(i)}`, i, null);
      }
      for (let i = totalEvents - 20; i < totalEvents; i += 1) {
        insertLegacyFinding(db, `f-${String(i)}`, `ev-${String(i)}`, {
          findingKey: `key-${String(i)}`,
        });
      }

      // First open: events copy hits its per-call cap without catching up,
      // so findings must not run at all this call.
      applyMigrations(db);
      expect((db.prepare('SELECT count(*) AS n FROM audit_events').get() as { n: number }).n).toBe(
        LEGACY_BACKFILL_MAX_ROWS_PER_CALL,
      );
      expect(
        (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(0);

      // Second open: events finish, and findings copies in the same call.
      applyMigrations(db);
      expect((db.prepare('SELECT count(*) AS n FROM audit_events').get() as { n: number }).n).toBe(
        totalEvents,
      );
      expect(
        (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(20);

      // Third open: no-op.
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(
        (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(20);
    } finally {
      db.close();
    }
  });

  it('resumes a batched findings copy across opens and is idempotent once caught up', () => {
    const db = preBackfillStore();
    try {
      // A handful of events (well under one call's budget) so the events
      // copy finishes in the first call, then findings alone spans two.
      for (let i = 0; i < 5; i += 1) {
        insertLegacyEvent(db, `ev-${String(i)}`, 1_000 + i, null);
      }
      const totalFindings = LEGACY_BACKFILL_MAX_ROWS_PER_CALL + 300;
      expect(totalFindings % LEGACY_BACKFILL_BATCH_SIZE).not.toBe(0); // exercises a partial final page
      for (let i = 0; i < totalFindings; i += 1) {
        insertLegacyFinding(db, `f-${String(i)}`, `ev-${String(i % 5)}`, {
          findingKey: `key-${String(i)}`,
          firstDetectedAt: i,
        });
      }

      // First open: migration 0013 applies, events fully copy, findings
      // copies exactly one call's worth and stops — NOT the whole table.
      applyMigrations(db);
      const afterFirst = (
        db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }
      ).n;
      expect(afterFirst).toBe(LEGACY_BACKFILL_MAX_ROWS_PER_CALL);

      // Second open ("reopen"): resumes from the watermark and finishes.
      applyMigrations(db);
      expect(
        (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(totalFindings);
      expect(
        (
          db.prepare('SELECT count(DISTINCT finding_key) AS n FROM inspection_findings').get() as {
            n: number;
          }
        ).n,
      ).toBe(totalFindings);

      // Third open: fully caught up, re-running is a cheap no-op.
      expect(() => {
        applyMigrations(db);
      }).not.toThrow();
      expect(
        (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(totalFindings);
    } finally {
      db.close();
    }
  });
});
