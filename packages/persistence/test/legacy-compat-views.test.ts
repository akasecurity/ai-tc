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
  legacyDropWouldDestroyRows,
  legacyRowMark,
} from '../src/migrations.ts';
import { DB_FILENAME } from '../src/paths.ts';
import { readOnlyStore } from './helpers/fault-injection.ts';
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
//
// A third kind opens a file that is NOT the store at all — a
// `aka.db.pre-drop.<ts>.<rand>.bak` snapshot — which `openRaw()` cannot reach,
// since it only ever opens `<home>/data/aka.db`. Those are read-only probes of
// a published copy and are closed in a `finally`.

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

/**
 * The pre-drop snapshot is owed only where the drop can destroy something.
 *
 * Migration 0014 drops two indexes and the `events`/`findings` tables, then
 * creates views; the rows in those two tables are the whole of what the
 * irreversible half can take. On a store this same open CREATED they were built
 * empty by the earlier migrations and never written to, so the snapshot copied a
 * freshly-built schema — half a megabyte, roughly half the bytes in a new data
 * dir, once on every new machine — and protected nothing.
 *
 * The pair of cases is the point. Dropping the copy on a store carrying real
 * pre-cutover history destroys that history, so "writes no backup" is only
 * worth asserting beside "still writes one, and still defers the drop when it
 * cannot" — which is what the populated cases below hold.
 */
describe('the pre-drop snapshot is taken only when the drop would destroy rows', () => {
  it('a fresh store first open leaves nothing beside aka.db — no pre-drop backup', () => {
    store.open().close();

    // The whole listing, not a `.pre-drop`-shaped absence check: an artifact
    // this package writes and nobody named is exactly what went unnoticed here
    // for as long as it did. Nothing but the store survives a clean close —
    // SQLite removes `-wal`/`-shm` when the last connection goes, and a
    // rollback `-journal` is gone at commit — so a sidecar showing up in this
    // list is a real signal rather than platform noise to filter away.
    //
    // Non-vacuous in both directions: the store itself has to BE there, or an
    // open that wrote nothing at all would satisfy an absence check.
    expect(readdirSync(store.dataDir).sort()).toEqual([DB_FILENAME]);
  });

  it('a store carrying legacy rows still gets its snapshot before the drop', () => {
    const file = seedPreCutoverFile();
    const seed = new DatabaseSync(file);
    seed.exec('PRAGMA foreign_keys = ON');
    insertLegacyEvent(seed, 'ev-1', 1_000, { repo: 'acme/api', filePath: 'src/a.ts' });
    insertLegacyFinding(seed, 'f-1', 'ev-1', { findingKey: 'key-1', firstDetectedAt: 500 });
    seed.close();

    store.open().close();

    const backups = readdirSync(store.dataDir).filter((f) => f.includes('.pre-drop.'));
    expect(backups).toHaveLength(1);
    const [backupName] = backups;
    if (!backupName) throw new Error('expected exactly one pre-drop backup file');
    const snap = new DatabaseSync(join(store.dataDir, backupName));
    try {
      // BEFORE the drop, which a row count alone cannot show: after the drop
      // these names are views over audit_events, and the backfill has already
      // copied the same row through, so `count(*)` reads 1 on a snapshot taken
      // from either side. What separates them is the OBJECT — a snapshot that
      // predates the drop holds real TABLES.
      expect(schemaObjectExists(snap, 'table', 'events')).toBe(true);
      expect(schemaObjectExists(snap, 'table', 'findings')).toBe(true);
      expect(schemaObjectExists(snap, 'view', 'events')).toBe(false);
      // …and it is a real copy of what stood there, not an empty file that
      // happens to carry the name.
      expect((snap.prepare('SELECT count(*) AS n FROM events').get() as { n: number }).n).toBe(1);
      expect((snap.prepare('SELECT count(*) AS n FROM findings').get() as { n: number }).n).toBe(1);
    } finally {
      snap.close();
    }

    // The live store is on the other side of that line, so the snapshot really
    // did capture an earlier state rather than a copy of the end state.
    const live = store.openRaw();
    expect(schemaObjectExists(live, 'view', 'events')).toBe(true);
    expect(schemaObjectExists(live, 'table', 'events')).toBe(false);
  });

  it('a failed snapshot on a store carrying legacy rows still defers the drop', (ctx) => {
    const file = seedPreCutoverFile();
    const db = new DatabaseSync(file);
    // WAL deliberately, and it is what makes this case mean anything. The fault
    // below is a directory nothing may create a file in — which stops the
    // snapshot staging a copy, but under the default DELETE journal would stop
    // the DROP's own rollback journal too, so the drop would defer for its own
    // reasons and the assertion would hold whether or not the backup is what
    // deferred it. Measured: with DELETE, removing the deferral entirely left
    // this case green. In WAL the transaction writes into a `-wal` that already
    // exists, so the snapshot is the only thing the fault reaches.
    const journalMode = (db.prepare('PRAGMA journal_mode = WAL').get() as { journal_mode: string })
      .journal_mode;
    db.exec('PRAGMA foreign_keys = ON');
    db.exec(
      'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
    );
    try {
      insertLegacyEvent(db, 'ev-1', 1_000, { repo: 'acme/api', filePath: 'src/a.ts' });
      insertLegacyFinding(db, 'f-1', 'ev-1', { findingKey: 'key-1', firstDetectedAt: 500 });
      // WAL is a filesystem capability, not a setting: it silently no-ops on
      // DrvFs and some network mounts (see dbSidecars), and there the drop
      // would need a rollback journal the fault also blocks — so the case
      // cannot separate the two and is meaningless rather than failing.
      if (journalMode !== 'wal' || !existsSync(`${file}-wal`)) {
        ctx.skip(`WAL did not engage on this filesystem (journal_mode=${journalMode})`);
        return;
      }

      // A real fault, not a stubbed throw, and the shared injector rather than a
      // private chmod: `dirOnly` tightens the data dir and leaves the store
      // writable, which is exactly the asymmetry this case needs — nothing may
      // CREATE the snapshot's staging directory, while the transaction below
      // appends to a `-wal` that already exists.
      const readOnly = readOnlyStore(file, { dirOnly: true, onCleanup: store.onCleanup });
      if (!readOnly.effective) {
        ctx.skip('the platform or privilege ignored the read-only directory mode');
        return;
      }

      applyLegacyDropMigration(db, file);

      // Nothing was published, and the history is still where it was.
      expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(false);
      expect(schemaObjectExists(db, 'table', 'events')).toBe(true);
      expect(schemaObjectExists(db, 'table', 'findings')).toBe(true);
      expect(schemaObjectExists(db, 'view', 'events')).toBe(false);
      expect(
        db.prepare('SELECT 1 FROM migration_ledger WHERE tag = ?').get(MIGRATION_0014_TAG),
      ).toBeUndefined();
      // A deferral that left the handle inside its BEGIN would make every later
      // write on it join a transaction nobody started.
      assertNoOpenTransaction(db);

      // The control, and the half that keeps the deferral above non-vacuous:
      // with the directory writable again the SAME call completes, so the drop
      // was blocked by the failed snapshot rather than by a fixture that could
      // never have dropped at all.
      readOnly.restore();
      applyLegacyDropMigration(db, file);
      expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(true);
      expect(schemaObjectExists(db, 'view', 'events')).toBe(true);
    } finally {
      db.close();
    }
  });

  /**
   * The condition is read off the store, so there is nothing for a caller to
   * lie about — `applyLegacyDropMigration` takes the handle and the path, and
   * gained no "skip the backup" argument to go with them.
   */
  describe('the condition comes from the store, never from the caller', () => {
    it('answers from the legacy tables themselves, and fails safe when it cannot read them', () => {
      const file = seedPreCutoverFile();
      const db = new DatabaseSync(file);
      db.exec('PRAGMA foreign_keys = ON');
      try {
        // Empty as the earlier migrations left them: nothing to protect.
        expect(legacyDropWouldDestroyRows(db)).toBe(false);

        // One row in EITHER table is enough — a backup owed for `findings`
        // alone must not be skipped because `events` happens to be empty.
        insertLegacyEvent(db, 'ev-1', 1_000, null);
        expect(legacyDropWouldDestroyRows(db)).toBe(true);
        insertLegacyFinding(db, 'f-1', 'ev-1');
        // `findings.event_id` references `events.id`, so emptying `events`
        // under it needs enforcement suspended — the state is what matters:
        // one legacy table empty, the other still holding a row.
        db.exec('PRAGMA foreign_keys = OFF');
        db.exec('DELETE FROM events');
        db.exec('PRAGMA foreign_keys = ON');
        expect(legacyDropWouldDestroyRows(db)).toBe(true);

        // A probe that cannot run is not evidence of an empty table. Answering
        // "false" here is the one wrong answer that loses data, so an
        // unreadable store is backed up rather than dropped.
        //
        // `findings` alone first, and that ordering is the whole point: the
        // loop probes `events` first and returns on ITS throw, so dropping both
        // never reaches the second arm at all. With `events` present and empty,
        // only the findings probe can produce this answer — narrowing the catch
        // to the events probe goes red here and nowhere else.
        db.exec('DROP TABLE findings');
        expect(legacyDropWouldDestroyRows(db)).toBe(true);

        db.exec('DROP TABLE events');
        expect(legacyDropWouldDestroyRows(db)).toBe(true);
      } finally {
        db.close();
      }
    });

    /**
     * The MARK half of that same read, which is what the recheck under the
     * write lock compares. A row arriving after the decision has to move it —
     * including on a store that was already non-empty, which is the window a
     * "does it hold rows" re-read cannot see, since the backfill copies without
     * deleting and such a store reads non-empty either way.
     */
    it('moves when a legacy row arrives, and holds still when nothing changes', () => {
      const file = seedPreCutoverFile();
      const db = new DatabaseSync(file);
      db.exec('PRAGMA foreign_keys = ON');
      try {
        const empty = legacyRowMark(db);
        expect(legacyRowMark(db)).toBe(empty); // stable across a re-read

        insertLegacyEvent(db, 'ev-1', 1_000, null);
        const oneEvent = legacyRowMark(db);
        expect(oneEvent).not.toBe(empty);

        // The case the mark exists for: already non-empty, and one more row
        // still moves it. `legacyDropWouldDestroyRows` reads true on both sides
        // here, so only the mark can tell them apart.
        insertLegacyEvent(db, 'ev-2', 2_000, null);
        expect(legacyRowMark(db)).not.toBe(oneEvent);
        expect(legacyDropWouldDestroyRows(db)).toBe(true);

        // …and the other table counts too.
        const beforeFinding = legacyRowMark(db);
        insertLegacyFinding(db, 'f-1', 'ev-1');
        expect(legacyRowMark(db)).not.toBe(beforeFinding);
      } finally {
        db.close();
      }
    });

    it('marks an unreadable table as equal to itself, never as a value that cannot match', () => {
      const file = seedPreCutoverFile();
      const db = new DatabaseSync(file);
      db.exec('PRAGMA foreign_keys = ON');
      try {
        db.exec('DROP TABLE findings');
        db.exec('DROP TABLE events');
        // A sentinel that never compares equal would defer the drop for ever on
        // a store in this shape — the failure the fail-safe must not create
        // while preventing the other one.
        expect(legacyRowMark(db)).toBe(legacyRowMark(db));
        expect(legacyDropWouldDestroyRows(db)).toBe(true);
      } finally {
        db.close();
      }
    });

    // Both polarities, because a third parameter could mean either "skip the
    // backup" or "keep it" and only one of them is caught by passing `true`.
    // Driven through a cast rather than a signature check: `Function.length`
    // stops at the first parameter with a DEFAULT, so `skipBackup = false`
    // leaves it reading 2 and a signature assertion passes while the flag is
    // wired up and honoured — measured, that is exactly what happened.
    for (const extra of [true, false]) {
      it(`ignores a ${String(extra)} a caller passes beyond the store and the path`, () => {
        const file = seedPreCutoverFile();
        const db = new DatabaseSync(file);
        db.exec('PRAGMA foreign_keys = ON');
        db.exec(
          'CREATE TABLE IF NOT EXISTS migration_ledger (tag TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)',
        );
        try {
          insertLegacyEvent(db, 'ev-1', 1_000, null);
          insertLegacyFinding(db, 'f-1', 'ev-1');
          // Precondition: a backup IS owed here, or "it was taken anyway" says
          // nothing about whether the extra argument was ignored.
          expect(legacyDropWouldDestroyRows(db)).toBe(true);

          // Every shape an opener that "knows" the store is fresh might reach
          // for, handed in at once.
          (applyLegacyDropMigration as (...args: unknown[]) => void)(db, file, extra, {
            skipBackup: extra,
            fresh: extra,
          });

          expect(readdirSync(store.dataDir).some((f) => f.includes('.pre-drop.'))).toBe(true);
        } finally {
          db.close();
        }
      });
    }
  });
});
