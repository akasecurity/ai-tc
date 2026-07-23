import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { EventKind, EventMetadata, SourceTool } from '@akasecurity/schema';
import { SQLITE_MIGRATIONS, toCaptureAttributes } from '@akasecurity/schema';

import {
  columnNames,
  evidenceExists,
  type EvidenceObject,
  evidenceObjects,
  indexExists,
  schemaObjectExists,
} from './db/migrations/introspection.ts';
import { inspectionDefinitionId, sourceProjectId } from './ids.ts';
import { bindParams } from './internal/rows.ts';
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
  // Copies whatever the retired events/findings pair still holds onto the
  // generalized audit_events/inspection_definitions/inspection_findings trio —
  // see runLegacyHistoryBackfill. Batched and resumable, so it never turns one
  // open into an unbounded pass over a large pre-existing store.
  runLegacyHistoryBackfill(db);
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

// --- legacy history backfill -------------------------------------------------
// Copies whatever the retired `events`/`findings` pair still holds onto the
// generalized `audit_events`/`inspection_definitions`/`inspection_findings`
// trio recordCapture now writes. The legacy tables are frozen (recordCapture
// no longer writes them), so this is a one-time drain, not an ongoing sync —
// but the store it drains can already be large, so the drain itself is
// batched and rowid-watermarked (`legacy_copy_watermark`, added by migration
// 0013) rather than a single pass: copying a large store's entire history in
// one transaction on the hook path — a hard 10s timeout, `busy_timeout` of
// only 2000ms — would be a zero-progress kill-and-retry loop. Each call here
// instead moves at most LEGACY_BACKFILL_MAX_ROWS_PER_CALL rows per table,
// committing every LEGACY_BACKFILL_BATCH_SIZE rows, so a crash or a slow disk
// mid-copy loses at most one uncommitted batch — the next open resumes from
// the watermark instead of restarting. A store already fully drained costs one
// cheap rowid-range probe per table on every open.

// Rows committed per transaction: small enough that one commit is cheap even
// under the hook's timeout, large enough that a modest local store finishes in
// a handful of opens. Exported so migrations.test.ts can size a fixture that
// exercises resumption without guessing at (or duplicating) the real cap.
export const LEGACY_BACKFILL_BATCH_SIZE = 200;

// Row budget per legacy table, per call: bounds one open's worth of work to a
// small constant regardless of how much history the store holds.
export const LEGACY_BACKFILL_MAX_ROWS_PER_CALL = 1000;

function getLegacyCopyWatermark(db: DatabaseSync, source: 'events' | 'findings'): number {
  const row = db
    .prepare('SELECT last_rowid AS lastRowid FROM legacy_copy_watermark WHERE source = ?')
    .get(source) as { lastRowid: number } | undefined;
  return row?.lastRowid ?? 0;
}

function setLegacyCopyWatermark(
  db: DatabaseSync,
  source: 'events' | 'findings',
  lastRowid: number,
): void {
  db.prepare(
    `INSERT INTO legacy_copy_watermark (source, last_rowid) VALUES (?, ?)
     ON CONFLICT(source) DO UPDATE SET last_rowid = excluded.last_rowid`,
  ).run(source, lastRowid);
}

// Shared batched-drain loop for the two legacy copies: reads the source's
// watermark, then repeatedly pages `selectStmt` (rowid > watermark, LIMIT
// LEGACY_BACKFILL_BATCH_SIZE) and hands each page to `handleRows` inside a single
// IMMEDIATE transaction that also advances + persists the watermark — so the row
// writes and the watermark advance commit atomically and a crash mid-backfill
// resumes at the last committed page. Returns true once the source is fully
// caught up (an empty page, or a short final page this call); false when it
// stopped at LEGACY_BACKFILL_MAX_ROWS_PER_CALL with rows still pending.
// `Row` is inferred from each caller's `handleRows` callback so both copies keep
// their own precise row shape without casting; the loop itself only ever touches
// `rowid`.
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters
function drainLegacyTable<Row extends { rowid: number }>(
  db: DatabaseSync,
  source: 'events' | 'findings',
  selectStmt: StatementSync,
  handleRows: (rows: Row[]) => void,
): boolean {
  let watermark = getLegacyCopyWatermark(db, source);
  let processed = 0;
  while (processed < LEGACY_BACKFILL_MAX_ROWS_PER_CALL) {
    const rows = selectStmt.all(watermark, LEGACY_BACKFILL_BATCH_SIZE) as Row[];
    if (rows.length === 0) return true;

    withTransaction(
      db,
      () => {
        handleRows(rows);
        watermark = rows[rows.length - 1]?.rowid ?? watermark;
        setLegacyCopyWatermark(db, source, watermark);
      },
      'IMMEDIATE',
    );
    processed += rows.length;
    if (rows.length < LEGACY_BACKFILL_BATCH_SIZE) return true;
  }
  return false;
}

// A legacy `events.metadata` blob is either NULL or JSON matching EventMetadata
// (camelCase keys) — see toEventRow. A row a pre-validation build once wrote
// could in principle hold malformed JSON; failing to parse it must not cost
// the row its place in history, so this degrades to "no metadata" rather than
// throwing (the event's own content/timestamps/ids still copy either way).
function parseLegacyEventMetadata(raw: string | null): EventMetadata | undefined {
  if (raw === null) return undefined;
  try {
    return JSON.parse(raw) as EventMetadata;
  } catch {
    return undefined;
  }
}

// The audit_events `attributes` bag for one legacy `events` row, reusing the
// exact capture-path mapping recordCapture writes new rows with (toCaptureAttributes)
// so a migrated row and a freshly-captured one carry the same shape.
function toLegacyAuditAttributesJson(row: {
  id: string;
  sourceTool: string;
  kind: string;
  occurredAt: number;
  contentHash: string;
  content: string;
  metadata: EventMetadata | undefined;
}): string {
  return JSON.stringify(
    toCaptureAttributes({
      id: row.id,
      sourceTool: row.sourceTool as SourceTool,
      kind: row.kind as EventKind,
      occurredAt: new Date(row.occurredAt).toISOString(),
      contentHash: row.contentHash,
      content: row.content,
      metadata: row.metadata,
    }),
  );
}

// Copies legacy `events` rows into `audit_events`, oldest-rowid-first, up to
// LEGACY_BACKFILL_MAX_ROWS_PER_CALL rows this call, committing every
// LEGACY_BACKFILL_BATCH_SIZE rows. Legacy ids are kept, so INSERT OR IGNORE
// keyed on `id` makes re-copying an already-migrated row a no-op. `sessionId`
// becomes both `parent_id` and `root_session_id` (mirroring recordCapture); its
// root row is stubbed on demand first (see stubRootStmt below) so the self-FK
// always resolves even for a session written after migration 0013 ran. Returns
// true once every legacy `events` row up to this call's view of the table has
// been copied — the signal `copyLegacyFindings` uses before it starts, so a
// finding's `audit_event_id` is never inserted ahead of the row it references.
function copyLegacyEvents(db: DatabaseSync): boolean {
  const selectStmt = db.prepare(
    `SELECT rowid AS rowid, id, source_tool AS sourceTool, kind, occurred_at AS occurredAt,
            content_hash AS contentHash, content, metadata
     FROM events WHERE rowid > ? ORDER BY rowid LIMIT ?`,
  );
  const insertStmt = db.prepare(
    `INSERT OR IGNORE INTO audit_events
       (id, parent_id, root_session_id, event_type, started_at, content, content_hash, attributes)
     VALUES (:id, :parentId, :rootSessionId, :eventType, :startedAt, :content, :contentHash, :attributes)`,
  );
  // On-demand session-root stub. Migration 0013 synthesized a root for every
  // legacy sessionId that existed WHEN IT RAN, but under version skew a
  // pre-cutover binary can write a NEW-session `events` row AFTER 0013
  // (ledgered, never re-run) and before the drop completes. INSERT OR IGNORE
  // does NOT suppress a foreign-key violation, so copying that row without its
  // root row present would throw, roll back the whole batch INCLUDING its
  // watermark advance, and — since runLegacyHistoryBackfill swallows the throw
  // and rows are ordered by rowid — wedge the drain on that same batch forever.
  // Stub the root first (first-write-wins on the id PK, harmless once 0013 or a
  // real SessionStart planted it) so the copy always makes forward progress.
  // The runtime equivalent of this stub is auditEvents.ensureSessionRoot.
  const stubRootStmt = db.prepare(
    `INSERT OR IGNORE INTO audit_events (id, event_type, started_at) VALUES (?, 'session', ?)`,
  );

  return drainLegacyTable(
    db,
    'events',
    selectStmt,
    (
      rows: {
        rowid: number;
        id: string;
        sourceTool: string;
        kind: string;
        occurredAt: number;
        contentHash: string;
        content: string;
        metadata: string | null;
      }[],
    ) => {
      for (const row of rows) {
        const metadata = parseLegacyEventMetadata(row.metadata);
        const sessionId = metadata?.sessionId ?? null;
        if (sessionId !== null) stubRootStmt.run(sessionId, row.occurredAt);
        insertStmt.run(
          bindParams({
            id: row.id,
            parentId: sessionId,
            rootSessionId: sessionId,
            eventType: row.kind,
            startedAt: row.occurredAt,
            content: row.content,
            contentHash: row.contentHash,
            attributes: toLegacyAuditAttributesJson({ ...row, metadata }),
          }),
        );
      }
    },
  );
}

// Copies legacy `findings` rows into `inspection_findings`, oldest-rowid-first,
// up to LEGACY_BACKFILL_MAX_ROWS_PER_CALL rows this call, committing every
// LEGACY_BACKFILL_BATCH_SIZE rows. The legacy table has no
// `inspection_definitions` row to point at — it carried `rule_id` plus a
// per-row `category`/`severity` inline — so this synthesizes ONE definition
// per DISTINCT (rule_id, category, severity) tuple seen (never one per
// rule_id: the same rule legitimately holds rows with different severities
// across pack updates, and collapsing them would silently relabel history).
// `version` is `unmigrated/<category>/<severity>`, distinct per tuple so the
// content-addressed definition id (sha256 of rule_id + version, minted the
// same way inspectionDefinitionId always is) never collides across tuples.
//
// The insert upserts on `finding_key`, not just `id`: post-cutover capture can
// already have written the SAME deterministic finding_key under a fresh
// (never-reused) id, so a plain insert would collide on the unique index —
// this reconciles the two rows' first_detected_at down to the EARLIEST of the
// two instead, tolerating either side being NULL.
function copyLegacyFindings(db: DatabaseSync): void {
  const selectStmt = db.prepare(
    `SELECT rowid AS rowid, id, event_id AS eventId, rule_id AS ruleId, category, severity,
            span_start AS spanStart, span_end AS spanEnd, masked_match AS maskedMatch,
            action_taken AS actionTaken, confidence, finding_key AS findingKey,
            first_detected_at AS firstDetectedAt
     FROM findings WHERE rowid > ? ORDER BY rowid LIMIT ?`,
  );
  const definitionStmt = db.prepare(
    `INSERT OR IGNORE INTO inspection_definitions
       (id, rule_id, name, category, severity, definition, version)
     VALUES (:id, :ruleId, :name, :category, :severity, :definition, :version)`,
  );
  const findingStmt = db.prepare(
    `INSERT INTO inspection_findings
       (id, audit_event_id, inspection_definition_id, classified_data_id,
        span_start, span_end, masked_match, action_taken, confidence,
        finding_key, first_detected_at)
     VALUES
       (:id, :auditEventId, :inspectionDefinitionId, NULL,
        :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence,
        :findingKey, :firstDetectedAt)
     ON CONFLICT(id) DO NOTHING
     ON CONFLICT (finding_key) DO UPDATE SET
       first_detected_at = CASE
         WHEN first_detected_at IS NULL THEN excluded.first_detected_at
         WHEN excluded.first_detected_at IS NULL THEN first_detected_at
         ELSE min(first_detected_at, excluded.first_detected_at)
       END`,
  );

  drainLegacyTable(
    db,
    'findings',
    selectStmt,
    (
      rows: {
        rowid: number;
        id: string;
        eventId: string;
        ruleId: string;
        category: string;
        severity: string;
        spanStart: number;
        spanEnd: number;
        maskedMatch: string;
        actionTaken: string;
        confidence: number;
        findingKey: string | null;
        firstDetectedAt: number | null;
      }[],
    ) => {
      // Per-page (inside the transaction), so a definition minted for one page
      // is reused across that page's findings but never leaks its id map across
      // batches — matching the crash-safe commit cadence.
      const definitionIds = new Map<string, string>();
      for (const row of rows) {
        const tupleKey = JSON.stringify([row.ruleId, row.category, row.severity]);
        let definitionId = definitionIds.get(tupleKey);
        if (definitionId === undefined) {
          const version = `unmigrated/${row.category}/${row.severity}`;
          definitionId = inspectionDefinitionId(row.ruleId, version);
          definitionStmt.run(
            bindParams({
              id: definitionId,
              ruleId: row.ruleId,
              name: row.ruleId,
              category: row.category,
              severity: row.severity,
              definition: '',
              version,
            }),
          );
          definitionIds.set(tupleKey, definitionId);
        }
        findingStmt.run(
          bindParams({
            id: row.id,
            auditEventId: row.eventId,
            inspectionDefinitionId: definitionId,
            spanStart: row.spanStart,
            spanEnd: row.spanEnd,
            maskedMatch: row.maskedMatch,
            actionTaken: row.actionTaken,
            confidence: row.confidence,
            findingKey: row.findingKey,
            firstDetectedAt: row.firstDetectedAt,
          }),
        );
      }
    },
  );
}

// Fail-open entry point: any failure (a locked store, a malformed row that
// slips past the defenses above) is logged and swallowed, never blocking the
// open. Findings only start once events reports fully caught up, so a
// finding's audit_event_id is never inserted ahead of its parent row.
export function runLegacyHistoryBackfill(db: DatabaseSync): void {
  try {
    const eventsCaughtUp = copyLegacyEvents(db);
    if (eventsCaughtUp) copyLegacyFindings(db);
  } catch (error) {
    akaWarn(`legacy history backfill failed: ${String(error)}`);
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
