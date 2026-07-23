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
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFinding, IngestEvent } from '@akasecurity/schema';
import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../src/database.ts';
import { schemaObjectExists } from '../src/db/migrations/introspection.ts';
import { LEGACY_BACKFILL_MAX_ROWS_PER_CALL } from '../src/migrations.ts';
import { DB_FILENAME } from '../src/paths.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-legacy-views-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

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
  const file = join(dir, DB_FILENAME);
  const raw = new DatabaseSync(file);
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
    const db = openLocalDatabase(dir);
    db.close();

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
      const db = openLocalDatabase(dir);
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

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
    openLocalDatabase(dir).close(); // a fresh store drops `events` -> view now

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
    expect(readdirSync(dir).some((f) => f.includes('.pre-drop.'))).toBe(false);

    const db = openLocalDatabase(dir);
    db.close();

    const backups = readdirSync(dir).filter((f) => f.includes('.pre-drop.'));
    expect(backups).toHaveLength(1);
    const [backupName] = backups;
    if (!backupName) throw new Error('expected exactly one pre-drop backup file');
    const backupPath = join(dir, backupName);
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
    for (let i = 0; i < totalEvents; i += 1) {
      insertLegacyEvent(raw, `ev-${String(i)}`, i, null);
    }
    raw.close();

    const first = openLocalDatabase(dir);
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
    expect(readdirSync(dir).some((f) => f.includes('.pre-drop.'))).toBe(false);

    // Second open resumes the copy, finishes, and only THEN drops.
    const second = openLocalDatabase(dir);
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
    expect(readdirSync(dir).some((f) => f.includes('.pre-drop.'))).toBe(true);
  });

  it('legacy SQL — verbatim from pre-cutover repository constructors — reads truthfully through the views', () => {
    const db = openLocalDatabase(dir);
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

    const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
    const db = openLocalDatabase(dir);
    db.close();
    const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
      const db = openLocalDatabase(dir);
      db.close();
      const raw = new DatabaseSync(join(dir, DB_FILENAME));
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
});
