import type { DatabaseSync } from 'node:sqlite';

import { SQLITE_MIGRATIONS } from '@akasecurity/schema';

import {
  columnNames,
  evidenceExists,
  type EvidenceObject,
  evidenceObjects,
  indexExists,
  schemaObjectExists,
} from './db/migrations/introspection.ts';
import { sourceProjectId } from './ids.ts';
import { withTransaction } from './internal/transactions.ts';
import { akaWarn } from './internal/warn.ts';

// --- migration-DDL introspection --------------------------------------------
// drizzle's generated SQLite DDL is rigidly formatted — backtick-quoted
// identifiers, one statement per `--> statement-breakpoint` — which is what
// makes the light parsing below safe.

function describeObject(object: EvidenceObject): string {
  return object.kind === 'column'
    ? `column ${object.table}.${object.name}`
    : `table ${object.name}`;
}

function splitStatements(sql: string): string[] {
  return sql
    .split(/-->\s*statement-breakpoint/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// The index a statement creates, or undefined for non-index statements.
// Leading SQL line comments are stripped first: hand-written custom migrations
// (e.g. 0009's expression index) open with a rationale block, and an index
// CREATE hidden behind comments would otherwise be misclassified as a
// non-index statement — replaying it on an adopted store instead of skipping.
function createdIndexName(statement: string): string | undefined {
  const body = statement.replace(/^(?:\s*--[^\n]*\n?)+/, '').trimStart();
  return /^CREATE (?:UNIQUE )?INDEX (?:IF NOT EXISTS )?`([^`]+)`/.exec(body)?.[1];
}

// Apply the canonical migrations the store hasn't yet, tracking applied
// migrations BY DRIZZLE JOURNAL TAG in the plugin-local `migration_ledger` table
// (no Drizzle ledger involved — the plugin owns migrations via node:sqlite;
// like `scan_ledger`, the ledger stays OUT of the canonical schema, which is
// drift-guarded against @akasecurity/schema). Then layer the plugin-local
// `synced_at` column, kept out of the canonical schema for the same reason.
//
// Tags, not a position count: state used to be "applied count" in
// PRAGMA user_version, which corrupted a store whose migration history was
// RENUMBERED — a feature branch shipped the shares tables as index 0002, then
// main landed the exceptions migration at 0002 and renumbered shares to 0003.
// That store's count said 3, so the applier replayed shares (throwing "table
// already exists") and never applied exceptions, silently under fail-open. Tags
// are stable across renumbering, so the ledger can't be fooled that way.
//
// An unledgered migration is reconciled by probing the tables/columns it
// creates: all present → adopt the tag without executing (backfilling any of
// its indexes the store lost); none present → genuinely pending, execute; SOME
// present → the schema has diverged from the migration history in a way we
// can't repair, so fail loudly instead of replaying or skipping. user_version
// is still stamped (write-only) so downgrading to an older count-based build
// stays a no-op.
export function applyMigrations(db: DatabaseSync): void {
  const legacyCount = (db.prepare('PRAGMA user_version').get() as { user_version: number })
    .user_version;
  db.exec(
    'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
  );
  const applied = new Set(
    (db.prepare('SELECT tag FROM migration_ledger').all() as { tag: string }[]).map((r) => r.tag),
  );
  const preLedgerStore = applied.size === 0 && legacyCount > 0;
  // OR IGNORE: two concurrent hook processes may race to reconcile the same tag.
  const record = db.prepare(
    'INSERT OR IGNORE INTO migration_ledger (tag, applied_at) VALUES (?, ?)',
  );

  for (const [index, migration] of SQLITE_MIGRATIONS.entries()) {
    if (applied.has(migration.tag)) continue;
    const evidence = evidenceObjects(migration.sql);
    const present = evidence.filter((o) => evidenceExists(db, o));

    if (present.length > 0 && present.length < evidence.length) {
      const missing = evidence.filter((o) => !present.includes(o));
      const message =
        `sqlite migration ${migration.tag} has no ledger row, but the store ` +
        `already has ${present.map(describeObject).join(', ')} while missing ` +
        `${missing.map(describeObject).join(', ')} — the schema diverged from the ` +
        `migration history; refusing to replay or skip.`;
      // The plugin's hook path swallows this throw fail-open, so "loudly" must
      // not depend on it propagating — write stderr first (the same channel as
      // the foreign-lineage reset in openLocalDatabase) so a plugin session
      // still shows WHY the store stopped persisting.
      akaWarn(message);
      throw new Error(`[aka] ${message}`);
    }

    // Already applied: every table/column this migration creates exists, so it
    // ran before the ledger did (under this or another position) — adopt the
    // tag, a replay would throw "already exists". For a migration with nothing
    // probeable (index- or data-only), the old position counter of a count-only
    // store is the only signal left, so trust it over replaying.
    const alreadyApplied =
      evidence.length > 0
        ? present.length === evidence.length
        : preLedgerStore && index < legacyCount;

    // drizzle emits table-recreates wrapped in PRAGMA foreign_keys=OFF/ON —
    // but PRAGMA foreign_keys is a silent NO-OP inside a transaction, so run
    // inside our BEGIN IMMEDIATE the recreate executes fully FK-enforced. The
    // 0005 recreate happens to be FK-safe (a child-only table), but a future
    // recreate of a REFERENCED table (inventory_asset, inventory) would blow
    // up mid-migration. Honor the envelope by hoisting: FKs off BEFORE the
    // transaction, verified (foreign_key_check) before commit, restored after.
    const wantsFkOff = /PRAGMA foreign_keys\s*=\s*OFF/i.test(migration.sql);

    // Non-index statements run only when the migration is genuinely pending.
    // Index statements run whenever the index is missing (backfilling an adopted
    // migration's lost index) and never when it exists (a divergent store may
    // have gained it out of band — recreating would throw). The existence check
    // happens AT EXECUTION TIME, statement by statement — not as an up-front
    // filter — because a drizzle table-recreate (CREATE __new / DROP old /
    // RENAME) drops the old table's indexes mid-migration: pre-filtering would
    // see the index present, skip its CREATE, and leave the rebuilt table
    // without its unique constraint (breaking every ON CONFLICT upsert on it).
    const statements = splitStatements(migration.sql);

    // IMMEDIATE takes the write lock up front (WAL + busy_timeout absorb a
    // concurrent opener), and the ledger row commits atomically with the DDL so
    // a crash can't strand a half-recorded migration.
    if (wantsFkOff) db.exec('PRAGMA foreign_keys = OFF');
    try {
      withTransaction(
        db,
        () => {
          for (const statement of statements) {
            const indexName = createdIndexName(statement);
            if (indexName === undefined) {
              if (alreadyApplied) continue;
            } else if (indexExists(db, indexName)) {
              continue;
            }
            db.exec(statement);
          }
          // With enforcement suspended, prove the migration left referential
          // integrity intact before committing — the same check drizzle's own
          // runner performs around a recreate.
          if (wantsFkOff && !alreadyApplied) {
            const violations = db.prepare('PRAGMA foreign_key_check').all();
            if (violations.length > 0) {
              throw new Error(
                `[aka] sqlite migration ${migration.tag} left ${String(violations.length)} foreign-key violation(s); rolling back.`,
              );
            }
          }
          record.run(migration.tag, Date.now());
        },
        'IMMEDIATE',
      );
    } finally {
      if (wantsFkOff) db.exec('PRAGMA foreign_keys = ON');
    }
  }

  if (legacyCount < SQLITE_MIGRATIONS.length) {
    // PRAGMA can't be parameterized; the value is our own integer literal.
    db.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length)}`);
  }
  // Both fact tables (`events` and `audit_events`) carry the plugin-local
  // `synced_at` bookkeeping column — see ensureSyncedAtColumn.
  ensureSyncedAtColumn(db, 'events');
  ensureSyncedAtColumn(db, 'audit_events');
  ensureScanLedgerTable(db);
  ensureBlockedDetectionsTable(db);
  ensureRuleProbeCacheTable(db);
  // SECURITY INVARIANT — belt-and-suspenders for the installed_packs write
  // gate. The 0006 migration's TRIGGER and gate-seed row are invisible to the
  // evidence probe above (evidenceObjects extracts only tables and ADDed
  // columns), so a store that acquired the gate table + recorded_by column out
  // of band — a drizzle-push-built dev store, or a future renumber — would
  // adopt the tag with the trigger NEVER created: ledger says migrated, gate
  // silently absent. Every other plugin-local object has an idempotent
  // installer for exactly this case; the one object that is a security control
  // must not be the exception. Runs unconditionally; no-op when present.
  ensureWriteGateTrigger(db);
  // Belt-and-suspenders for the token-usage generated columns: the canonical
  // migration above adds them on fresh stores, but a store whose `user_version`
  // already counted past the meta migration (an early-adopter SQLite file) would
  // otherwise never gain them. Guarded by table_xinfo so it is a no-op when they
  // already exist.
  ensureTokenUsageColumns(db);
  reconcileSourceProjectIds(db);
}

// SQLite generated-column DDL for the six token-usage facets: the four counts are
// integer, model/provider are text, all VIRTUAL via json_extract.
//
// CANONICAL SOURCE is the `0001_adorable_marten_broadcloak` migration in
// `@akasecurity/schema` (packages/schema/src/drizzle/sqlite-ddl.ts), itself generated from
// the local-store drizzle column defs in `packages/schema/src/drizzle/local/sqlite.ts`. This
// list is an INTENTIONAL re-hardcoding, not a careless copy: `@akasecurity/persistence` is
// forbidden from importing `@akasecurity/schema`'s drizzle layer (boundary rule — it may
// only touch the Zod/DDL re-exports, never the drizzle internals), so we cannot
// share the column objects directly. Any column added/removed/renamed in that
// migration MUST be mirrored here. `migrations.test.ts` guards the column-NAME set
// against drift so a mismatch fails loudly instead of silently skipping a facet.
export const TOKEN_USAGE_COLUMNS: readonly { name: string; ddl: string }[] = [
  {
    name: 'input_tokens',
    ddl: "ALTER TABLE audit_events ADD COLUMN input_tokens integer GENERATED ALWAYS AS (json_extract(attributes, '$.input_tokens')) VIRTUAL",
  },
  {
    name: 'output_tokens',
    ddl: "ALTER TABLE audit_events ADD COLUMN output_tokens integer GENERATED ALWAYS AS (json_extract(attributes, '$.output_tokens')) VIRTUAL",
  },
  {
    name: 'cache_creation_input_tokens',
    ddl: "ALTER TABLE audit_events ADD COLUMN cache_creation_input_tokens integer GENERATED ALWAYS AS (json_extract(attributes, '$.cache_creation_input_tokens')) VIRTUAL",
  },
  {
    name: 'cache_read_input_tokens',
    ddl: "ALTER TABLE audit_events ADD COLUMN cache_read_input_tokens integer GENERATED ALWAYS AS (json_extract(attributes, '$.cache_read_input_tokens')) VIRTUAL",
  },
  {
    name: 'model',
    ddl: "ALTER TABLE audit_events ADD COLUMN model text GENERATED ALWAYS AS (json_extract(attributes, '$.model')) VIRTUAL",
  },
  {
    name: 'provider',
    ddl: "ALTER TABLE audit_events ADD COLUMN provider text GENERATED ALWAYS AS (json_extract(attributes, '$.provider')) VIRTUAL",
  },
];

// In-place backfill of the token-usage generated columns for existing
// `audit_events` stores. SQLite permits ADD COLUMN for VIRTUAL generated columns
// (unlike STORED). CRITICAL: on a fresh store the canonical migration already
// created these columns, so a blind ADD would error — the guard makes each ADD a
// no-op when the column is present. We probe with PRAGMA table_xinfo, NOT
// table_info: table_info omits generated columns, so it would never see these and
// the ADD would fail with "duplicate column name". Idempotent, like
// ensureSyncedAtColumn.
function ensureTokenUsageColumns(db: DatabaseSync): void {
  const existing = new Set(columnNames(db, 'audit_events', { includeGenerated: true }));
  for (const column of TOKEN_USAGE_COLUMNS) {
    if (!existing.has(column.name)) {
      db.exec(column.ddl);
    }
  }
}

// Heal orphaned duplicate `source_project` rows left by an id-derivation change:
// a legacy store derived the id from [tenantId, 'source_project', url] with a
// per-store RANDOM tenantId, the tenant-free store from ['source_project', url] —
// so the same repo url hashes to two different ids across plugin versions, and
// with no unique index on `url` the upsert (keyed on id) never reconciles the old
// row, which then renders as a duplicate project in the Inventory list. The legacy
// id is unrecoverable (the random tenantId is gone with the legacy store), so a
// legacy row is detected as `id != sourceProjectId(url)` and folded into the
// canonical row: every reference is repointed first (foreign_keys is ON, so order
// matters), the observation window is widened (older first_seen, newer last_seen),
// and the legacy row is deleted. Sample projects (the retired demo dataset in
// historical stores; also the test fixtures) are deliberately keyed
// `sample:project:<slug>` and must NOT be re-keyed — the `sample:` prefix is
// excluded (sample-purge.ts deletes those rows instead).
//
// Runs on EVERY open rather than once via the migration ledger: an older plugin
// bundle sharing the store may keep re-inserting legacy rows, and the pass is a
// cheap no-op (one small SELECT) when none exist. Fail-open in full: the duplicate
// is cosmetic, so ANY failure — the initial scan included — is logged and swallowed
// and never blocks the store from opening; a failure mid-fold also rolls back.
export function reconcileSourceProjectIds(db: DatabaseSync): void {
  try {
    // last_seen DESC so that when several legacy rows share a url and no canonical
    // row exists yet, the newest sighting is folded first and thus wins the
    // name/attributes tie-break deterministically (see the fold upsert below).
    const rows = db
      .prepare(
        `SELECT id, url, name, attributes, first_seen AS firstSeen, last_seen AS lastSeen
         FROM source_project
         WHERE url IS NOT NULL AND id NOT LIKE 'sample:%'
         ORDER BY last_seen DESC, id`,
      )
      .all() as {
      id: string;
      url: string;
      name: string | null;
      attributes: string;
      firstSeen: number;
      lastSeen: number;
    }[];
    // Pair each row with its canonical id ONCE, then keep only the drifted ones.
    const legacy = rows
      .map((row) => ({ row, canonicalId: sourceProjectId(row.url) }))
      .filter(({ row, canonicalId }) => row.id !== canonicalId);
    if (legacy.length === 0) return;

    // Prepared once, run per legacy row.
    const foldProject = db.prepare(
      `INSERT INTO source_project (id, url, name, attributes, first_seen, last_seen)
         VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         first_seen = min(first_seen, excluded.first_seen),
         last_seen = max(last_seen, excluded.last_seen)`,
    );
    const repointAudit = db.prepare(
      'UPDATE audit_events SET source_project_id = ? WHERE source_project_id = ?',
    );
    const repointCallSite = db.prepare(
      'UPDATE share_call_site SET project_id = ? WHERE project_id = ?',
    );
    // project_file / file_access_override are UNIQUE(project_id, path): a path
    // recorded under BOTH ids collides on repoint, so drop the legacy copy in
    // favor of the canonical one first. Statements prepared once per table.
    const pathTables = (['project_file', 'file_access_override'] as const).map((table) => ({
      dropCollisions: db.prepare(
        `DELETE FROM ${table} WHERE project_id = ?
           AND path IN (SELECT path FROM ${table} WHERE project_id = ?)`,
      ),
      repoint: db.prepare(`UPDATE ${table} SET project_id = ? WHERE project_id = ?`),
    }));
    const deleteLegacy = db.prepare('DELETE FROM source_project WHERE id = ?');

    withTransaction(
      db,
      () => {
        for (const { row, canonicalId } of legacy) {
          // The FIRST writer for this url keeps name/attributes; every later fold
          // only widens the observation window (min first_seen, max last_seen). A
          // real canonical row, if one exists, is that first writer and so keeps its
          // name/attributes — the same Type-1 overwrite-to-latest the upsert uses
          // (the canonical row is the current plugin's write). With no canonical row
          // and several legacy rows, the last_seen-DESC ordering makes the newest
          // sighting the first writer, so the winner is deterministic.
          foldProject.run(
            canonicalId,
            row.url,
            row.name,
            row.attributes,
            row.firstSeen,
            row.lastSeen,
          );
          repointAudit.run(canonicalId, row.id);
          for (const { dropCollisions, repoint } of pathTables) {
            dropCollisions.run(row.id, canonicalId);
            repoint.run(canonicalId, row.id);
          }
          repointCallSite.run(canonicalId, row.id);
          deleteLegacy.run(row.id);
        }
      },
      'IMMEDIATE',
    );
  } catch (error) {
    // Same channel as the applier's loud paths — visible in a plugin session even
    // though the failure is swallowed.
    akaWarn(`source_project id reconcile failed: ${String(error)}`);
  }
}

// True when the open store belongs to a foreign, tenant-bearing lineage, which
// is incompatible with the tenant-free lineage this package migrates. Both track
// state as a bare PRAGMA user_version starting at tag 0000, so the applier alone
// can't tell them apart: such an `aka.db` (user_version already past this count)
// skips every migration, keeps its tenant-bearing schema, and then fails every
// write on `NOT NULL: events.tenant_id` — silently, because the plugin is
// fail-open. openLocalDatabase uses this to reset the store instead.
//
// A fresh/empty db (no `events` table yet) is NOT foreign — the normal migration
// path creates the tenant-free tables.
export function isForeignSqliteLineage(db: DatabaseSync): boolean {
  if (schemaObjectExists(db, 'table', 'tenants')) return true;
  return columnNames(db, 'events').includes('tenant_id');
}

// `synced_at` is an additive, plugin-local bookkeeping column that existing
// stores already carry; installing it here (outside the append-only canonical
// migrations) keeps every store column-compatible regardless of which release
// created it. Guarded by table_info so it is applied exactly once per table,
// idempotently.
function ensureSyncedAtColumn(db: DatabaseSync, table: 'events' | 'audit_events'): void {
  if (!columnNames(db, table).includes('synced_at')) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN synced_at integer`);
  }
}

// Worktree-scan bookkeeping: which files the scanner has already run under which
// ruleset, so a /aka:scan re-run skips unchanged files without re-reading them.
// Plugin-local, so like `synced_at` it stays out of the canonical schema and is
// created here, idempotently. Tenant-free like the rest of the local store —
// one row per absolute path.
function ensureScanLedgerTable(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS scan_ledger (
    path TEXT PRIMARY KEY,
    mtime TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ruleset_hash TEXT NOT NULL,
    scanned_at INTEGER NOT NULL
  )`);
}

// Idempotent installer for the installed_packs write gate (canonical source:
// the 0006_magenta_flatman migration) — the in-database control that stops
// already-shipped legacy binaries from rewriting installed pack content.
// DDL mirrors the migration byte-for-byte modulo the
// IF NOT EXISTS / OR IGNORE guards; any semantic change to the gate MUST land
// in the migration first and be mirrored here. Unlike the other ensure*
// helpers this one guards a SECURITY invariant, so it self-heals the trigger
// and seed row on ANY store shape — including stores whose migration tag was
// adopted via the evidence probe (which cannot see triggers or rows) without
// the trigger ever executing.
function ensureWriteGateTrigger(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS \`_pack_write_gate\` (
	\`id\` integer PRIMARY KEY NOT NULL,
	\`open\` integer DEFAULT 0 NOT NULL,
	CONSTRAINT "ck_pack_write_gate_single_row" CHECK("_pack_write_gate"."id" = 1)
)`);
  db.exec('INSERT OR IGNORE INTO _pack_write_gate (id, open) VALUES (1, 0)');
  db.exec(`CREATE TRIGGER IF NOT EXISTS trg_installed_packs_write_gate
BEFORE UPDATE OF version, name, rules_json ON installed_packs
WHEN (SELECT open FROM _pack_write_gate WHERE id = 1) IS NOT 1
BEGIN SELECT RAISE(IGNORE); END`);
}

// Just-blocked detection bookkeeping for the exception approve flow: when an
// enforcing policy blocks/redacts, the hook records what fired — a short
// reference plus the rule and the KEYED FINGERPRINT of the value (never the
// value itself) — so the CLI can grant an exception without the user retyping
// the secret. Rows live ~30 minutes (swept on every write by the repository).
// Plugin-local, so like `scan_ledger` it stays out of the canonical schema —
// where the durable `exceptions` table lives — and is created here,
// idempotently.
function ensureBlockedDetectionsTable(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS blocked_detections (
    reference TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    value_fingerprint TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    masked_value TEXT NOT NULL,
    session_id TEXT,
    repo TEXT,
    blocked_at INTEGER NOT NULL
  )`);
}

// Runtime ReDoS timing cache: one row per rule (by content hash of its
// pattern+flags) recording the one-time adversarial-probe verdict for a
// regex rule sourced from a pulled or custom pack. Plugin-local, so like
// `scan_ledger` it stays out of the canonical schema and is created here,
// idempotently.
function ensureRuleProbeCacheTable(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS rule_probe_cache (
    rule_key TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    worst_probe_ms REAL NOT NULL,
    checked_at INTEGER NOT NULL
  )`);
}
