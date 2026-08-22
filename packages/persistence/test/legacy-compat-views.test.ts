// The legacy `events`/`findings` compatibility views (migration 0013 in
// @akasecurity/schema): the tables recordCapture no longer writes are dropped
// once the batched history backfill has fully drained them, and replaced with
// read-only views of the same name projecting the legacy column shapes out of
// audit_events/inspection_definitions/inspection_findings. This suite pins:
//   - a fresh store lands on the views immediately (nothing to drain);
//   - the store re-opens repeatedly without throwing (the regression test for
//     the installer brick — see migrations.ts's ensureSyncedAtColumn fix);
//   - a populated pre-cutover store drains, backs itself up, and drops without
//     losing a row;
//   - the FROZEN SQL a pre-cutover binary's repositories execute reads
//     truthfully through the views, and its rare (eager, prepare()-time)
//     writes behave exactly as documented — events' plain INSERT fails only
//     at run time, findings' ON CONFLICT upsert fails at prepare() (SQLite
//     refuses to plan an upsert against any view, trigger or not — a known,
//     unavoidable, documented gap for that one already-shipped SQL shape).
import { randomUUID } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';
import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { schemaObjectExists } from '../src/db/migrations/introspection.ts';
import {
  applyLegacyDropMigration,
  backupBeforeLegacyDrop,
  LEGACY_BACKFILL_MAX_ROWS_PER_CALL,
  legacyDropNeedsBackup,
  MIGRATION_SEEDED_TABLES,
} from '../src/migrations.ts';
import { DB_FILENAME, dbSidecars } from '../src/paths.ts';
import { corruptStore } from './helpers/fault-injection.ts';
import { useTempStore } from './helpers/temp-store.ts';
import { assertNoOpenTransaction } from './helpers/transactions.ts';

// This suite drives real on-disk SQLite migrations, a batched history backfill,
// and pre-drop backups against temp stores — all fsync-bound work. On a
// slow-flush filesystem (e.g. Windows CI, where flushes are slow and highly
// variable) the heaviest cases run past vitest's 20s default, so give the whole
// file generous headroom rather than let legitimate slow-disk timing trip it.
vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });

const store = useTempStore('aka-legacy-views-');

// Raw connections here are split on purpose. A plain read of the store goes
// through `store.openRaw()`, which closes it at teardown whatever the body did.
// The fixture handles do NOT: each is opened to leave the store at one point in
// the migration and closed again before the next `store.open()` drains a little
// further, and the backfill and the drop are what those opens run — a handle
// left live across one changes what it does. `openRaw()` holds every handle it
// hands out until teardown, so it is the wrong tool wherever the close IS the
// setup.

const MIGRATION_0013_TAG = '0013_legacy_history_backfill_support';
const MIGRATION_0014_TAG = '0014_drop_legacy_events_findings';

// Builds a REAL on-disk store frozen just before the backfill/drop pair —
// every migration through 0012 applied, legacy `events`/`findings` still real
// tables — so a test can seed pre-cutover rows into them exactly like an
// already-installed binary would have, then hand the same file to
// openLocalDatabase and observe the real open-time behavior (backfill,
// backup, drop) rather than calling applyMigrations directly against a bare
// DatabaseSync.
function seedPreCutoverFile(): string {
  const file = join(store.dataDir, DB_FILENAME);
  const raw = new DatabaseSync(file);
  // Fixture durability is irrelevant — the file is thrown away after the test.
  // Replaying ~12 migrations against the default DELETE journal pays one fsync
  // AND one rollback-journal file create/delete per statement, which on the
  // Windows CI runner's NTFS (no fsync coalescing, slow metadata ops) under
  // parallel test-file load overruns the timeout. MEMORY journal + synchronous
  // OFF drop both costs; the on-disk file the migrations write is still a valid
  // store for openLocalDatabase to reopen.
  raw.exec('PRAGMA journal_mode = MEMORY');
  raw.exec('PRAGMA synchronous = OFF');
  raw.exec('PRAGMA foreign_keys = ON');
  for (const migration of SQLITE_MIGRATIONS) {
    if (migration.tag === MIGRATION_0013_TAG) continue;
    if (migration.tag === MIGRATION_0014_TAG) continue;
    raw.exec(migration.sql);
  }
  raw.close();
  return file;
}

// The state the drop is really reached in: every migration applied EXCEPT the
// drop itself, so `legacy_copy_watermark` (0013) exists and the legacy pair is
// still a pair of real tables. seedPreCutoverFile() freezes one migration
// earlier, which is the right fixture for the drain but the wrong one for any
// question about the store's own upgrade record.
function seedPreDropFile(): string {
  const file = seedPreCutoverFile();
  const raw = new DatabaseSync(file);
  // Same reasoning as seedPreCutoverFile's own pragmas: fixture durability is
  // irrelevant, and the default DELETE journal's per-statement fsync is what
  // pushes this file past its timeout on the Windows runner.
  raw.exec('PRAGMA journal_mode = MEMORY');
  raw.exec('PRAGMA synchronous = OFF');
  try {
    const sql = SQLITE_MIGRATIONS.find((m) => m.tag === MIGRATION_0013_TAG)?.sql;
    if (sql === undefined) throw new Error(`missing migration ${MIGRATION_0013_TAG}`);
    raw.exec(sql);
  } finally {
    raw.close();
  }
  return file;
}

function insertLegacyEvent(
  raw: DatabaseSync,
  id: string,
  occurredAt: number,
  metadata: Record<string, unknown> | null,
  overrides: { sourceTool?: string; kind?: string } = {},
): void {
  raw
    .prepare(
      `INSERT INTO events (id, source_tool, kind, occurred_at, content_hash, content, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      overrides.sourceTool ?? 'claude-code',
      overrides.kind ?? 'code_change',
      occurredAt,
      `hash-${id}`,
      `content for ${id}`,
      metadata === null ? null : JSON.stringify(metadata),
    );
}

function insertLegacyFinding(
  raw: DatabaseSync,
  id: string,
  eventId: string,
  overrides: { findingKey?: string | null; firstDetectedAt?: number | null } = {},
): void {
  raw
    .prepare(
      `INSERT INTO findings
         (id, event_id, rule_id, category, severity, span_start, span_end,
          masked_match, action_taken, confidence, finding_key, first_detected_at)
       VALUES (?, ?, 'secrets/aws-access-key', 'secret', 'critical', 0, 10, 'AKIA…MPLE', 'block', 0.9, ?, ?)`,
    )
    .run(id, eventId, overrides.findingKey ?? null, overrides.firstDetectedAt ?? null);
}

describe('legacy events/findings compatibility views', () => {
  it('a fresh store lands on the views immediately — nothing to drain', () => {
    const db = store.open();
    db.close();

    const raw = store.openRaw();
    try {
      expect(schemaObjectExists(raw, 'table', 'events')).toBe(false);
      expect(schemaObjectExists(raw, 'table', 'findings')).toBe(false);
      expect(schemaObjectExists(raw, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(raw, 'view', 'findings')).toBe(true);

      // The legacy column SHAPE survives on the view: every column an
      // already-shipped repository's SQL names by column list, plus the
      // plugin-local `synced_at` a pre-cutover binary's ensureSyncedAtColumn
      // probes for (projected NULL so that probe never ALTERs the view).
      const eventsColumns = (raw.prepare('PRAGMA table_info(events)').all() as { name: string }[])
        .map((c) => c.name)
        .sort();
      expect(eventsColumns).toEqual(
        [
          'id',
          'source_tool',
          'kind',
          'occurred_at',
          'content_hash',
          'content',
          'synced_at',
          'metadata',
        ].sort(),
      );
      const findingsColumns = (
        raw.prepare('PRAGMA table_info(findings)').all() as { name: string }[]
      )
        .map((c) => c.name)
        .sort();
      expect(findingsColumns).toEqual(
        [
          'id',
          // A view has no rowid of its own — re-exposed explicitly under that
          // name so a legacy reader ordering by `f.rowid` (recentFindings)
          // still resolves the column. See the migration's own comment.
          'rowid',
          'event_id',
          'rule_id',
          'category',
          'severity',
          'span_start',
          'span_end',
          'masked_match',
          'action_taken',
          'confidence',
          'finding_key',
          'first_detected_at',
        ].sort(),
      );
    } finally {
      raw.close();
    }
  });

  it('re-opens successfully, repeatedly, after the drop — the installer-brick regression test', () => {
    for (let i = 0; i < 5; i += 1) {
      const db = store.open();
      // Basic operations keep working on every reopen, not just the open call.
      const id = randomUUID();
      const ev: IngestEvent = {
        id,
        sourceTool: 'claude-code',
        kind: 'code_change',
        occurredAt: new Date().toISOString(),
        contentHash: `hash-${String(i)}`,
        content: 'x',
      };
      const finding: DetectedFinding = {
        id: randomUUID(),
        eventId: id,
        ruleId: 'secrets/aws-access-key',
        category: 'secret',
        severity: 'critical',
        span: { start: 0, end: 4 },
        maskedMatch: 'AKIA…MPLE',
        actionTaken: 'block',
        confidence: 0.9,
      };
      expect(() => {
        db.recordCapture(ev, [finding]);
      }).not.toThrow();
      db.close();
    }

    const raw = store.openRaw();
    try {
      expect(schemaObjectExists(raw, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(raw, 'view', 'findings')).toBe(true);
      // One row per reopen — every recordCapture call actually persisted.
      expect((raw.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(5);
    } finally {
      raw.close();
    }
  });

  it('the events view exposes synced_at so a pre-cutover binary never ALTERs the view', () => {
    // A pre-cutover binary still ships ensureSyncedAtColumn(db, 'events'), which
    // ALTERs `events` to add its plugin-local `synced_at` column whenever that
    // column is absent. Against a store a newer binary already dropped `events`
    // on, `events` is a VIEW — and `ALTER TABLE <view> ADD COLUMN` is rejected
    // by SQLite ("Cannot add a column to a view"), a hard, NON-fail-open crash
    // of the whole open (it propagates out of applyMigrations/openLocalDatabase),
    // i.e. exactly the skew crash these views exist to prevent. The view
    // projects `synced_at` so the old probe's column guard short-circuits.
    // (The new binary's own ensureSyncedAtColumn was separately fixed to skip a
    // view; this covers the already-installed OLD binary, which cannot be.)
    store.open().close(); // a fresh store drops `events` -> view now

    const raw = store.openRaw();
    try {
      const cols = (raw.prepare('PRAGMA table_info(events)').all() as { name: string }[]).map(
        (c) => c.name,
      );
      // The projected column an old ensureSyncedAtColumn(db, 'events') looks for.
      expect(cols).toContain('synced_at');

      // The exact pre-cutover probe: it ALTERs only when the column is absent,
      // so with the projection present it is a no-op and never throws.
      expect(() => {
        if (!cols.includes('synced_at')) {
          raw.exec('ALTER TABLE events ADD COLUMN synced_at integer');
        }
      }).not.toThrow();

      // The fatal error the projection avoids: ALTERing the view unconditionally
      // (what the old probe would do without the projection) is what crashes.
      expect(() => {
        raw.exec('ALTER TABLE events ADD COLUMN synced_at integer');
      }).toThrow(/view/i);
    } finally {
      raw.close();
    }
  });

  it('drains, backs up, and drops a populated pre-cutover store without losing a row', () => {
    const file = seedPreCutoverFile();
    const raw = new DatabaseSync(file);
    raw.exec('PRAGMA foreign_keys = ON');
    insertLegacyEvent(raw, 'ev-1', 1_000, { repo: 'acme/api', filePath: 'src/a.ts' });
    insertLegacyEvent(raw, 'ev-2', 2_000, { repo: 'acme/api', filePath: 'src/b.ts' });
    insertLegacyFinding(raw, 'f-1', 'ev-1', { findingKey: 'key-1', firstDetectedAt: 500 });
    insertLegacyFinding(raw, 'f-2', 'ev-2', { findingKey: 'key-2', firstDetectedAt: 1_500 });
    raw.close();

    // No backup exists yet — the drop hasn't run.
    expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(false);

    const db = store.open();
    db.close();

    const backups = readdirSync(store.dataDir).filter((f) => f.includes('.pre-drop.'));
    expect(backups).toHaveLength(1);
    const [backupName] = backups;
    if (!backupName) throw new Error('expected exactly one pre-drop backup file');
    const backupPath = join(store.dataDir, backupName);
    expect(existsSync(backupPath)).toBe(true);

    // The backup is a genuine, complete, openable SQLite database — not a
    // truncated or half-written copy — and still holds every legacy row
    // exactly as it stood right before the drop.
    const backupDb = new DatabaseSync(backupPath);
    try {
      expect((backupDb.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(
        2,
      );
      expect(
        (backupDb.prepare('SELECT count(*) AS n FROM findings').get() as { n: number }).n,
      ).toBe(2);
    } finally {
      backupDb.close();
    }

    // The live store: legacy tables gone, views in their place, and every row
    // preserved in the generalized tables (row counts, distinct finding_key
    // count, and per-key first_detected_at all survive the migration).
    const post = new DatabaseSync(file);
    try {
      expect(schemaObjectExists(post, 'table', 'events')).toBe(false);
      expect(schemaObjectExists(post, 'table', 'findings')).toBe(false);
      expect(schemaObjectExists(post, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(post, 'view', 'findings')).toBe(true);

      expect(
        (
          post
            .prepare(
              `SELECT count(*) AS n FROM audit_events WHERE event_type IN ('prompt','response','code_change','tool_use')`,
            )
            .get() as { n: number }
        ).n,
      ).toBe(2);
      expect(
        (post.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n,
      ).toBe(2);
      expect(
        (
          post
            .prepare(
              'SELECT count(DISTINCT finding_key) AS n FROM inspection_findings WHERE finding_key IS NOT NULL',
            )
            .get() as { n: number }
        ).n,
      ).toBe(2);
      const firstDetected = post
        .prepare(
          'SELECT finding_key AS findingKey, first_detected_at AS firstDetectedAt FROM inspection_findings ORDER BY finding_key',
        )
        .all() as { findingKey: string; firstDetectedAt: number }[];
      expect(firstDetected).toEqual([
        { findingKey: 'key-1', firstDetectedAt: 500 },
        { findingKey: 'key-2', firstDetectedAt: 1_500 },
      ]);

      // The views themselves still answer with the same counts.
      expect((post.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(2);
      expect((post.prepare('SELECT count(*) AS n FROM findings').get() as { n: number }).n).toBe(2);
    } finally {
      post.close();
    }
  });

  it('a store still mid-copy keeps its real legacy tables — the drop never fires on a partial drain', () => {
    const file = seedPreCutoverFile();
    const raw = new DatabaseSync(file);
    raw.exec('PRAGMA foreign_keys = ON');
    // More legacy events than one open's backfill budget, so the FIRST
    // openLocalDatabase call cannot finish draining — the drop must not run.
    const totalEvents = LEGACY_BACKFILL_MAX_ROWS_PER_CALL + 50;
    // Seed the whole pre-cutover table in a single transaction: as individual
    // auto-committed INSERTs the fixture pays one journal fsync per row (~1k of
    // them), which on a slow-flush filesystem overruns the test timeout. The
    // rows still land with sequential rowids, so the backfill's watermark paging
    // is unchanged.
    raw.exec('BEGIN');
    for (let i = 0; i < totalEvents; i += 1) {
      insertLegacyEvent(raw, `ev-${String(i)}`, i, null);
    }
    raw.exec('COMMIT');
    // The whole point of this fixture is that it holds MORE rows than one open's
    // backfill budget. A transaction still open here commits none of them, and
    // the "still mid-copy" assertions below would then hold on an empty store —
    // for the wrong reason, and identically.
    assertNoOpenTransaction(raw);
    raw.close();

    const first = store.open();
    first.close();

    const afterFirst = new DatabaseSync(file);
    try {
      // Still mid-copy: the legacy tables are untouched real tables, and no
      // backup has been taken (the drop never got far enough to need one).
      expect(schemaObjectExists(afterFirst, 'table', 'events')).toBe(true);
      expect(schemaObjectExists(afterFirst, 'table', 'findings')).toBe(true);
      expect(schemaObjectExists(afterFirst, 'view', 'events')).toBe(false);
      expect(
        (
          afterFirst
            .prepare('SELECT count(*) AS n FROM audit_events WHERE event_type = ?')
            .get('code_change') as { n: number }
        ).n,
      ).toBe(LEGACY_BACKFILL_MAX_ROWS_PER_CALL);
    } finally {
      afterFirst.close();
    }
    expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(false);

    // Second open resumes the copy, finishes, and only THEN drops.
    const second = store.open();
    second.close();

    const afterSecond = new DatabaseSync(file);
    try {
      expect(schemaObjectExists(afterSecond, 'table', 'events')).toBe(false);
      expect(schemaObjectExists(afterSecond, 'view', 'events')).toBe(true);
      expect(
        (afterSecond.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n,
      ).toBe(totalEvents);
    } finally {
      afterSecond.close();
    }
    expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(true);
  });

  it('legacy SQL — verbatim from pre-cutover repository constructors — reads truthfully through the views', () => {
    const db = store.open();
    const sessionId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
    });
    const eventId = randomUUID();
    const ev: IngestEvent = {
      id: eventId,
      sourceTool: 'claude-code',
      kind: 'code_change',
      occurredAt: new Date('2026-01-01T00:00:00.000Z').toISOString(),
      contentHash: 'hash-legacy-sql',
      content: 'const key = "..."',
      metadata: { sessionId, repo: 'acme/api', filePath: 'src/a.ts', toolName: 'Edit' },
    };
    const finding: DetectedFinding = {
      id: randomUUID(),
      eventId,
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      severity: 'critical',
      span: { start: 0, end: 10 },
      maskedMatch: 'AKIA…MPLE',
      actionTaken: 'block',
      confidence: 0.95,
    };
    db.recordCapture(ev, [finding]);
    db.close();

    const raw = store.openRaw();
    try {
      // findings.ts (pre-cutover): recentFindings.
      const recent = raw
        .prepare(
          `SELECT f.id, f.event_id, f.rule_id, f.category, f.severity, f.masked_match,
                  f.action_taken, f.confidence, e.occurred_at, e.source_tool, e.kind
           FROM findings f JOIN events e ON e.id = f.event_id
           ORDER BY e.occurred_at DESC, f.rowid DESC
           LIMIT :limit`,
        )
        .all({ limit: 50 }) as { rule_id: string; masked_match: string; source_tool: string }[];
      expect(recent).toHaveLength(1);
      expect(recent[0]).toMatchObject({
        rule_id: 'secrets/aws-access-key',
        masked_match: 'AKIA…MPLE',
        source_tool: 'claude-code',
      });

      // findings.ts (pre-cutover): sessionFindingsCount.
      const sessionCount = raw
        .prepare(
          `SELECT count(*) AS n FROM findings f
             JOIN events e ON e.id = f.event_id
            WHERE json_extract(e.metadata, '$.sessionId') = :sessionId`,
        )
        .get({ sessionId }) as { n: number };
      expect(sessionCount.n).toBe(1);

      // findings.ts (pre-cutover): healthSummary — a BARE `FROM findings`, no join.
      const total = raw.prepare('SELECT count(*) AS n FROM findings').get() as { n: number };
      expect(total.n).toBe(1);

      // security.ts (pre-cutover): severitySummary.
      const severity = raw
        .prepare(
          `SELECT f.severity AS severity, COUNT(*) AS count
             FROM findings f JOIN events e ON e.id = f.event_id
            GROUP BY f.severity`,
        )
        .all() as { severity: string; count: number }[];
      expect(severity).toEqual([{ severity: 'critical', count: 1 }]);

      // security.ts (pre-cutover): topSources (metadata.repo).
      const topSources = raw
        .prepare(
          `SELECT json_extract(e.metadata, '$.repo') AS repo, count(*) AS c
             FROM findings f JOIN events e ON e.id = f.event_id
            WHERE json_extract(e.metadata, '$.repo') IS NOT NULL
            GROUP BY repo`,
        )
        .all() as { repo: string; c: number }[];
      expect(topSources).toEqual([{ repo: 'acme/api', c: 1 }]);

      // resolutions.ts (pre-cutover): openAtRestStmt shape.
      const openAtRest = raw
        .prepare(
          `SELECT DISTINCT f.finding_key AS finding_key
             FROM findings f JOIN events e ON e.id = f.event_id
            WHERE e.kind = 'code_change'
              AND json_extract(e.metadata, '$.filePath') = :path
              AND f.finding_key IS NOT NULL`,
        )
        .all({ path: 'src/a.ts' });
      // This capture carried no findingKey, so it never surfaces here — the
      // point is that the statement PREPARES and RUNS at all against the view.
      expect(openAtRest).toEqual([]);

      // detections.ts (pre-cutover): countFindingsLast30d shape.
      const last30d = raw
        .prepare(
          `SELECT count(*) AS n FROM findings f JOIN events e ON e.id = f.event_id
            WHERE e.occurred_at >= ? AND f.rule_id IN (?)`,
        )
        .get(0, 'secrets/aws-access-key') as { n: number };
      expect(last30d.n).toBe(1);
    } finally {
      raw.close();
    }
  });

  it('events.ts (pre-cutover): the eager INSERT prepares against the view and fails only at run time', () => {
    const db = store.open();
    db.close();
    const raw = store.openRaw();
    try {
      let stmt: ReturnType<DatabaseSync['prepare']> | undefined;
      expect(() => {
        stmt = raw.prepare(
          `INSERT INTO events (id, source_tool, kind, occurred_at, content_hash, content, metadata)
           VALUES (:id, :sourceTool, :kind, :occurredAt, :contentHash, :content, :metadata)`,
        );
      }).not.toThrow();
      expect(() => {
        stmt?.run({
          id: 'x',
          sourceTool: 'cli',
          kind: 'prompt',
          occurredAt: 1,
          contentHash: 'h',
          content: 'c',
          metadata: null,
        });
      }).toThrow(/read-only/);
    } finally {
      raw.close();
    }
  });

  it(
    'findings.ts (pre-cutover): the eager ON CONFLICT upsert fails at prepare() — a documented, ' +
      'unavoidable gap (SQLite refuses to plan an upsert against any view)',
    () => {
      const db = store.open();
      db.close();
      const raw = store.openRaw();
      try {
        expect(() => {
          raw.prepare(
            `INSERT INTO findings (id, event_id, rule_id, category, severity, span_start, span_end, masked_match, action_taken, confidence, finding_key, first_detected_at)
             VALUES (:id, :eventId, :ruleId, :category, :severity, :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence, :findingKey,
                     (SELECT occurred_at FROM events WHERE id = :eventId))
             ON CONFLICT (finding_key) DO UPDATE SET
               event_id = excluded.event_id,
               category = excluded.category,
               severity = excluded.severity,
               span_start = excluded.span_start,
               span_end = excluded.span_end,
               masked_match = excluded.masked_match,
               action_taken = excluded.action_taken,
               confidence = excluded.confidence`,
          );
        }).toThrow(/UPSERT/i);
      } finally {
        raw.close();
      }
    },
  );

  it('re-running the legacy drop against post-drop schema is a no-op (concurrent serialization loser)', () => {
    const file = seedPreCutoverFile();
    const db = new DatabaseSync(file);
    db.exec('PRAGMA foreign_keys = ON');
    db.exec(
      'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
    );
    try {
      // Empty legacy tables => already drained. First call is the winner.
      applyLegacyDropMigration(db, undefined);
      expect(schemaObjectExists(db, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(db, 'view', 'findings')).toBe(true);
      // Second call mimics the serialization loser holding the write lock over
      // the winner's post-drop schema; the in-txn ledger recheck must no-op it
      // instead of throwing "no such index" / "use DROP VIEW".
      expect(() => {
        applyLegacyDropMigration(db, undefined);
      }).not.toThrow();
      expect(schemaObjectExists(db, 'view', 'events')).toBe(true);
    } finally {
      db.close();
    }
  });

  it('the legacy drop completes (not defers) when an events index is absent — DROP INDEX IF EXISTS', () => {
    // The adopted-tag / absent-index divergence, applied directly so the drop
    // sees the missing index (going through openLocalDatabase would rebuild the
    // 0010 index first). With a bare DROP INDEX this throws "no such index",
    // which the fail-open wrapper then swallows and DEFERS the drop (no view) —
    // so IF EXISTS is what lets the drop actually complete here.
    const file = seedPreCutoverFile();
    const db = new DatabaseSync(file);
    db.exec('PRAGMA foreign_keys = ON');
    db.exec(
      'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
    );
    db.exec('DROP INDEX `idx_events_session_id`');
    try {
      expect(() => {
        applyLegacyDropMigration(db, undefined);
      }).not.toThrow();
      expect(schemaObjectExists(db, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(db, 'table', 'events')).toBe(false);
    } finally {
      db.close();
    }
  });

  // --- the pre-drop snapshot is owed, or it is not -------------------------
  // The drop is reached on the FIRST open of every brand-new store, where the
  // legacy pair was created empty milliseconds earlier by this same open. The
  // snapshot there copies a freshly built schema and nothing else — a second
  // full copy of the store file on every install. legacyDropNeedsBackup is what
  // separates that from a store carrying history; these pin both sides of it.

  it('a brand-new store takes no pre-drop backup — there is nothing in it to protect', () => {
    const db = store.open();
    db.close();

    // The drop really did run on this open (otherwise "no backup" would hold
    // for the wrong reason — a deferred drop needs no backup either).
    const raw = store.openRaw();
    try {
      expect(schemaObjectExists(raw, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(raw, 'table', 'events')).toBe(false);
    } finally {
      raw.close();
    }

    const entries = readdirSync(store.dataDir).sort();
    // Positive control FIRST. The absence check below is a filter, and a filter
    // over an empty directory is empty — so on its own it passes just as well
    // against a store that was never written at all.
    expect(entries).toContain(DB_FILENAME);
    // Only the store itself and its own sidecars are on disk: no `.pre-drop.`
    // copy, and no staging directory left behind by one either. Measured on
    // arm64 macOS / Node 24 the list is exactly ['aka.db'] — every sidecar is
    // checkpointed away by the close above — but the sidecars are part of the
    // store rather than a copy of it, so they are allowed rather than pinned.
    const allowed = new Set([DB_FILENAME, ...dbSidecars(DB_FILENAME)]);
    expect(entries.filter((f) => !allowed.has(f))).toEqual([]);
  });

  it('a store carrying legacy rows is still snapshotted before the drop', () => {
    const file = seedPreCutoverFile();
    const raw = new DatabaseSync(file);
    raw.exec('PRAGMA foreign_keys = ON');
    insertLegacyEvent(raw, 'ev-keep', 1_000, null);
    raw.close();

    const db = store.open();
    db.close();

    expect(readdirSync(store.dataDir).filter((f) => f.includes('.pre-drop.'))).toHaveLength(1);

    // And the snapshot was taken on the way THROUGH the drop, not because the
    // drop deferred — a deferral leaves a backup behind too, so the count above
    // does not distinguish them on its own.
    const after = store.openRaw();
    try {
      expect(schemaObjectExists(after, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(after, 'table', 'events')).toBe(false);
    } finally {
      after.close();
    }
  });

  it('a failed snapshot still defers the drop on a store carrying legacy rows', () => {
    const file = seedPreDropFile();
    const db = new DatabaseSync(file);
    db.exec('PRAGMA foreign_keys = ON');
    db.exec(
      'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
    );
    // Real legacy history, so the snapshot is unambiguously owed.
    insertLegacyEvent(db, 'ev-doomed', 1_000, null);
    try {
      expect(legacyDropNeedsBackup(db)).toBe(true);

      // Point the snapshot at a data dir that does not exist: staging the copy
      // throws, on every platform and without needing a chmod or a privilege.
      const unreachable = join(store.dataDir, 'no-such-dir', DB_FILENAME);
      expect(() => {
        applyLegacyDropMigration(db, unreachable);
      }).not.toThrow();

      // Deferred, not proceeded-without-one: the legacy pair is untouched, no
      // view was created, and the tag is not ledgered — the next open retries.
      expect(schemaObjectExists(db, 'table', 'events')).toBe(true);
      expect(schemaObjectExists(db, 'view', 'events')).toBe(false);
      expect(
        db.prepare('SELECT 1 FROM migration_ledger WHERE tag = ?').get(MIGRATION_0014_TAG),
      ).toBeUndefined();
      expect((db.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(1);
      // A deferred drop must not leave its own transaction open behind it.
      assertNoOpenTransaction(db);

      // Positive control on the SAME store and the same call: the only thing
      // that changes is whether the snapshot can be written. With a reachable
      // path the drop completes and the copy lands — so the deferral above is
      // attributable to the failed snapshot rather than to anything else about
      // this fixture.
      applyLegacyDropMigration(db, file);
      expect(schemaObjectExists(db, 'view', 'events')).toBe(true);
      expect(schemaObjectExists(db, 'table', 'events')).toBe(false);
      expect(readdirSync(store.dataDir).filter((f) => f.includes('.pre-drop.'))).toHaveLength(1);
    } finally {
      db.close();
    }
  });

  it('a row anywhere outside the legacy pair still owes the backup — a mid-upgrade store', () => {
    const file = seedPreDropFile();
    const db = new DatabaseSync(file);
    db.exec('PRAGMA foreign_keys = ON');
    try {
      // The legacy pair is empty, exactly as on a brand-new store...
      expect((db.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(0);
      expect(legacyDropNeedsBackup(db)).toBe(false);

      // ...but a store part-way through the upgrade carries its drained history
      // in audit_events, and that is evidence the snapshot is owed.
      db.prepare(
        "INSERT INTO audit_events (id, event_type, started_at) VALUES ('sess-1', 'session', 1000)",
      ).run();
      expect(legacyDropNeedsBackup(db)).toBe(true);
    } finally {
      db.close();
    }
  });

  it('a drained watermark owes the backup — the case the general rule has to cover', () => {
    // The watermark is the store's own record that legacy rows were once copied
    // out of it, and it is written atomically with those rows (drainLegacyTable).
    // It gets no special case in legacyDropNeedsBackup: `legacy_copy_watermark`
    // is a plain table, so a row in it is evidence under the general rule like
    // any other. This is what would go red if it were ever added to
    // MIGRATION_SEEDED_TABLES — which would cost a genuinely-upgraded store its
    // snapshot the day `audit_events` gains a retention sweep and such a store
    // can present as otherwise empty.
    const file = seedPreDropFile();
    const db = new DatabaseSync(file);
    db.exec('PRAGMA foreign_keys = ON');
    try {
      expect(legacyDropNeedsBackup(db)).toBe(false);
      db.prepare(
        "INSERT INTO legacy_copy_watermark (source, last_rowid) VALUES ('events', 42)",
      ).run();
      expect(legacyDropNeedsBackup(db)).toBe(true);
    } finally {
      db.close();
    }
  });

  it('an unanswerable probe backs up rather than assuming there is nothing to protect', () => {
    // A store whose schema cannot be read at all answers neither way, and the
    // unanswered case has to take the backup. Without the guard the throw would
    // escape applyMigrations and fail the whole open, where today a store this
    // damaged merely defers the drop.
    // The store is left in the state the PRODUCTION caller probes: mid-open,
    // before openLocalDatabase seeds the default policies. A fully-opened store
    // is the wrong control here — its seeded `policies` rows are real evidence,
    // so the probe rightly says "back up" and the assertion below would have to
    // be bought with an allowlist entry the production path never needs.
    const file = seedPreDropFile();

    // Positive control on the very same store: healthy and carrying nothing,
    // the probe says there is nothing to protect. Only the damage below can
    // flip it, so the assertion after it cannot hold for the boring reason.
    const healthy = new DatabaseSync(file);
    try {
      expect(legacyDropNeedsBackup(healthy)).toBe(false);
    } finally {
      healthy.close();
    }

    corruptStore(file, 'header', { store });
    const damaged = new DatabaseSync(file);
    try {
      expect(legacyDropNeedsBackup(damaged)).toBe(true);
    } finally {
      damaged.close();
    }
  });

  it('MIGRATION_SEEDED_TABLES is pinned exactly — widening it hides real evidence', () => {
    // The ONE hand-maintained input to legacyDropNeedsBackup, and the only way
    // to skip a backup that was owed. A table listed there stops counting as
    // evidence, so adding one that holds user data — `exceptions`,
    // `secret_vault`, `inspection_findings` — makes a store holding only that
    // read as "nothing to protect". Measured: with those three added, every
    // other test in this package still passed, so nothing but an exact set
    // makes the widening loud.
    //
    // Both entries are written by applyMigrations itself, BEFORE the drop is
    // reached: the ledger it records its own progress in, and the
    // installed_packs write gate's single control row (ensureWriteGateTrigger).
    // `policies` is the near miss and is deliberately absent — seedDefaults()
    // runs in openLocalDatabase AFTER applyMigrations, so the table is empty at
    // the probe point and listing it would only have hidden a user's
    // customized rows.
    expect([...MIGRATION_SEEDED_TABLES].sort()).toEqual(['_pack_write_gate', 'migration_ledger']);
  });

  it('pre-drop backup is a sidecar-free snapshot that includes WAL-resident committed rows', () => {
    const file = join(store.dataDir, DB_FILENAME);
    const db = new DatabaseSync(file);
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('CREATE TABLE audit_events (id INTEGER PRIMARY KEY, v TEXT)');
    for (let i = 0; i < 5; i += 1) {
      db.prepare('INSERT INTO audit_events (v) VALUES (?)').run(`r${String(i)}`);
    }
    // Committed but WAL-resident (never checkpointed): a raw copy of the main db
    // file would miss these rows and copy the -wal sidecar into a torn set.
    expect(existsSync(`${file}-wal`)).toBe(true);

    const backup = backupBeforeLegacyDrop(db, file);
    try {
      expect(existsSync(backup)).toBe(true);
      // The property a copyFileSync-of-main-only backup violates.
      expect(existsSync(`${backup}-wal`)).toBe(false);
      expect(existsSync(`${backup}-shm`)).toBe(false);
      // The WAL-resident committed rows were captured.
      const snap = new DatabaseSync(backup);
      try {
        expect(
          (snap.prepare('SELECT count(*) AS n FROM audit_events').get() as { n: number }).n,
        ).toBe(5);
      } finally {
        snap.close();
      }
      // The live handle stays usable afterward.
      expect(() => {
        db.prepare('INSERT INTO audit_events (v) VALUES (?)').run('after');
      }).not.toThrow();
    } finally {
      db.close();
    }
  });
});
