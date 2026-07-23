// recordCapture flipped from writing the legacy events/findings pair to
// writing the generalized audit_events/inspection_definitions/inspection_findings
// trio (see database.ts). These tests pin the NEW writer's behavior directly —
// the legacy events/findings tests in database.test.ts and the repository
// suites that read through them are EXPECTED to fail now that recordCapture no
// longer populates those tables; re-pointing those readers is a separate task.
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { DetectedFindingWithKey, IngestEvent } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../src/database.ts';
import { captureId } from '../src/ids.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-record-capture-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const MASKED = 'AKIA…MPLE';

function event(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: 'hash',
    content: 'here is a key <redacted>',
    ...overrides,
  };
}

function finding(overrides: Partial<DetectedFindingWithKey> = {}): DetectedFindingWithKey {
  return {
    id: randomUUID(),
    eventId: randomUUID(),
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 14, end: 34 },
    maskedMatch: MASKED,
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

// A second read connection to the same WAL file, for raw SQL the repository
// surface doesn't expose (mirrors meta.test.ts's helper).
function raw(): DatabaseSync {
  return new DatabaseSync(join(dir, 'aka.db'));
}
function count(db: DatabaseSync, table: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

describe('recordCapture — audit/inspection trio', () => {
  it('writes one audit_events row and one inspection_findings row wired to its definition', () => {
    const db = openLocalDatabase(dir);
    const ev = event({ kind: 'code_change', contentHash: 'hash-1' });
    db.recordCapture(ev, [finding()]);

    const auditEventId = captureId(null, 'hash-1');
    const r = raw();
    expect(count(r, 'audit_events')).toBe(1);
    expect(count(r, 'inspection_findings')).toBe(1);
    expect(count(r, 'inspection_definitions')).toBe(1);
    // The cutover is a full replacement, not a dual-write.
    expect(count(r, 'events')).toBe(0);
    expect(count(r, 'findings')).toBe(0);

    const auditRow = r
      .prepare(
        'SELECT event_type, content, content_hash, root_session_id FROM audit_events WHERE id = ?',
      )
      .get(auditEventId) as {
      event_type: string;
      content: string;
      content_hash: string;
      root_session_id: string | null;
    };
    expect(auditRow.event_type).toBe('code_change');
    expect(auditRow.content).toBe(ev.content);
    expect(auditRow.content_hash).toBe('hash-1');
    expect(auditRow.root_session_id).toBeNull();

    const findingRow = r
      .prepare('SELECT audit_event_id, masked_match, action_taken FROM inspection_findings')
      .get() as { audit_event_id: string; masked_match: string; action_taken: string };
    expect(findingRow.audit_event_id).toBe(auditEventId);
    expect(findingRow.masked_match).toBe(MASKED);
    expect(findingRow.action_taken).toBe('block');

    r.close();
    db.close();
  });

  it.each(['prompt', 'response', 'code_change', 'tool_use'] as const)(
    'maps event.kind=%s onto audit_events.event_type unchanged',
    (kind) => {
      const db = openLocalDatabase(dir);
      const ev = event({ kind, contentHash: `hash-${kind}` });
      db.recordCapture(ev, []);

      const auditEventId = captureId(null, `hash-${kind}`);
      const r = raw();
      const row = r
        .prepare('SELECT event_type FROM audit_events WHERE id = ?')
        .get(auditEventId) as { event_type: string } | undefined;
      expect(row?.event_type).toBe(kind);
      r.close();
      db.close();
    },
  );

  it('maps every legacy metadata key onto its CaptureAttributes name, excluding sessionId', () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    // The real root exists up front so this test is orthogonal to the
    // orphan-session stub behavior (covered separately below).
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
    });

    const ev = event({
      kind: 'tool_use',
      contentHash: 'hash-attrs',
      metadata: {
        sessionId,
        repo: 'org/repo',
        filePath: 'src/index.ts',
        toolName: 'Bash',
        gitignored: true,
        wholeFile: true,
        model: 'claude-sonnet-4-6',
        turnIndex: 3,
        correlationId: '11111111-1111-1111-1111-111111111111',
        traceId: 'a'.repeat(32),
        exceptionIds: ['22222222-2222-2222-2222-222222222222'],
      },
    });
    db.recordCapture(ev, []);

    const auditEventId = captureId(sessionId, 'hash-attrs');
    const r = raw();
    const row = r.prepare('SELECT attributes FROM audit_events WHERE id = ?').get(auditEventId) as {
      attributes: string;
    };
    const attributes = JSON.parse(row.attributes) as Record<string, unknown>;
    expect(attributes).toEqual({
      source_tool: 'claude-code',
      repo: 'org/repo',
      file_path: 'src/index.ts',
      tool_name: 'Bash',
      gitignored: true,
      whole_file: true,
      model: 'claude-sonnet-4-6',
      turn_index: 3,
      correlation_id: '11111111-1111-1111-1111-111111111111',
      trace_id: 'a'.repeat(32),
      exception_ids: ['22222222-2222-2222-2222-222222222222'],
    });
    // sessionId became the FK, never an attribute, under either casing.
    expect('sessionId' in attributes).toBe(false);
    expect('session_id' in attributes).toBe(false);
    r.close();
    db.close();
  });

  it('stamps parent_id/root_session_id to the session when present, NULL when absent', () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
    });

    const withSession = event({
      kind: 'prompt',
      contentHash: 'hash-with-session',
      metadata: { sessionId },
    });
    db.recordCapture(withSession, []);
    const withSessionId = captureId(sessionId, 'hash-with-session');

    const withoutSession = event({ kind: 'prompt', contentHash: 'hash-no-session' });
    db.recordCapture(withoutSession, []);
    const withoutSessionId = captureId(null, 'hash-no-session');

    const r = raw();
    const a = r
      .prepare('SELECT parent_id, root_session_id FROM audit_events WHERE id = ?')
      .get(withSessionId) as { parent_id: string | null; root_session_id: string | null };
    expect(a.parent_id).toBe(sessionId);
    expect(a.root_session_id).toBe(sessionId);

    const b = r
      .prepare('SELECT parent_id, root_session_id FROM audit_events WHERE id = ?')
      .get(withoutSessionId) as { parent_id: string | null; root_session_id: string | null };
    expect(b.parent_id).toBeNull();
    expect(b.root_session_id).toBeNull();
    r.close();
    db.close();
  });
});

// The verified trap: `INSERT OR IGNORE` does not suppress a foreign-key
// violation, only UNIQUE/PK/NOT NULL/CHECK. Without the session-root stub, a
// capture referencing a sessionId with no audit_events root row raises
// SQLITE_CONSTRAINT, and failOpenTransaction rolls back and swallows it —
// silently dropping the entire capture (event AND every finding). Orphan
// sessions are realistic: SessionStart's own root write is itself fail-open,
// and its once-per-session claim marks "attempted", not "succeeded", so a
// failed first attempt is never retried.
describe('recordCapture — orphan-session FK trap', () => {
  it('persists the capture (event + findings) even when its session has no audit_events root row yet', () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID(); // deliberately never written by SessionStart
    const ev = event({ kind: 'tool_use', contentHash: 'hash-orphan', metadata: { sessionId } });

    expect(() => {
      db.recordCapture(ev, [finding({ findingKey: 'fk-orphan-1' })]);
    }).not.toThrow();

    const auditEventId = captureId(sessionId, 'hash-orphan');
    const r = raw();
    // The capture itself persisted — not silently dropped by a rolled-back txn.
    const captureRow = r
      .prepare('SELECT root_session_id FROM audit_events WHERE id = ?')
      .get(auditEventId) as { root_session_id: string | null } | undefined;
    expect(captureRow).toBeDefined();
    expect(captureRow?.root_session_id).toBe(sessionId);
    expect(count(r, 'inspection_findings')).toBe(1);

    // A stub session root was minted to satisfy the FK: same id, event_type
    // 'session', no dimensions/attributes of its own.
    const stub = r
      .prepare(
        'SELECT event_type, root_session_id, host_id, attributes FROM audit_events WHERE id = ?',
      )
      .get(sessionId) as {
      event_type: string;
      root_session_id: string | null;
      host_id: string | null;
      attributes: string | null;
    };
    expect(stub.event_type).toBe('session');
    expect(stub.root_session_id).toBeNull();
    expect(stub.host_id).toBeNull();
    expect(stub.attributes).toBeNull();

    r.close();
    db.close();
  });

  it('the stub session root is a harmless no-op once the real root landed first', () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    // The REAL root, written first (as SessionStart normally does), carrying
    // real attribute data.
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
      attributes: { provider: 'anthropic' },
    });

    const ev = event({ kind: 'prompt', contentHash: 'hash-real-root', metadata: { sessionId } });
    db.recordCapture(ev, []);

    const r = raw();
    const row = r.prepare('SELECT attributes FROM audit_events WHERE id = ?').get(sessionId) as {
      attributes: string | null;
    };
    // First-write-wins: the capture's stub attempt never overwrote the real
    // root's attributes.
    expect(row.attributes && (JSON.parse(row.attributes) as Record<string, unknown>)).toEqual({
      provider: 'anthropic',
    });
    r.close();
    db.close();
  });

  it('a capture with no sessionId at all never mints a stray session row', () => {
    const db = openLocalDatabase(dir);
    const ev = event({ kind: 'code_change', contentHash: 'hash-no-session-2' });
    db.recordCapture(ev, []);

    const r = raw();
    // Only the capture's own row — root_session_id NULL passes the FK trivially,
    // so no session stub was ever needed.
    expect(count(r, 'audit_events')).toBe(1);
    r.close();
    db.close();
  });
});

describe('recordCapture — finding_key reconciliation', () => {
  it('a re-detected finding_key reconciles onto the original row, preserving first_detected_at', () => {
    const db = openLocalDatabase(dir);
    const sessionId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: new Date().toISOString(),
    });

    const first = event({
      kind: 'code_change',
      contentHash: 'hash-v1',
      occurredAt: new Date(Date.now() - 60_000).toISOString(),
      metadata: { sessionId, filePath: 'src/config.ts' },
    });
    db.recordCapture(first, [finding({ findingKey: 'fk-recon-1', maskedMatch: 'AKIA…OLD' })]);

    const second = event({
      kind: 'code_change',
      contentHash: 'hash-v2',
      occurredAt: new Date().toISOString(),
      metadata: { sessionId, filePath: 'src/config.ts' },
    });
    db.recordCapture(second, [
      finding({
        findingKey: 'fk-recon-1',
        maskedMatch: 'AKIA…NEW',
        actionTaken: 'redact',
        confidence: 0.5,
      }),
    ]);

    const r = raw();
    expect(count(r, 'inspection_findings')).toBe(1); // reconciled, not duplicated
    const row = r
      .prepare(
        `SELECT masked_match, action_taken, confidence, audit_event_id, first_detected_at
         FROM inspection_findings WHERE finding_key = ?`,
      )
      .get('fk-recon-1') as {
      masked_match: string;
      action_taken: string;
      confidence: number;
      audit_event_id: string;
      first_detected_at: number;
    };
    expect(row.masked_match).toBe('AKIA…NEW'); // refreshed
    expect(row.action_taken).toBe('redact'); // refreshed
    expect(row.confidence).toBe(0.5); // refreshed
    expect(row.audit_event_id).toBe(captureId(sessionId, 'hash-v2')); // refreshed to latest capture
    expect(row.first_detected_at).toBe(new Date(first.occurredAt).getTime()); // preserved
    r.close();
    db.close();
  });

  it('an in-flight finding with no finding_key never collides across two captures', () => {
    const db = openLocalDatabase(dir);
    const e1 = event({ kind: 'prompt', contentHash: 'hash-p1' });
    const e2 = event({ kind: 'prompt', contentHash: 'hash-p2' });
    db.recordCapture(e1, [finding()]); // no findingKey
    db.recordCapture(e2, [finding()]); // no findingKey

    const r = raw();
    expect(count(r, 'inspection_findings')).toBe(2); // NULL never conflicts in a unique index
    r.close();
    db.close();
  });
});

describe('recordCapture — inspection_definitions upsert', () => {
  it('collapses repeated findings for the same ruleId onto one definition row', () => {
    const db = openLocalDatabase(dir);
    const e1 = event({ kind: 'code_change', contentHash: 'hash-def-1' });
    const e2 = event({ kind: 'code_change', contentHash: 'hash-def-2' });
    db.recordCapture(e1, [finding({ ruleId: 'secrets/aws-access-key' })]);
    db.recordCapture(e2, [finding({ ruleId: 'secrets/aws-access-key' })]);

    const r = raw();
    expect(count(r, 'inspection_definitions')).toBe(1);
    const def = r.prepare('SELECT rule_id, name, version FROM inspection_definitions').get() as {
      rule_id: string;
      name: string;
      version: string;
    };
    expect(def.rule_id).toBe('secrets/aws-access-key');
    expect(def.name).toBe('secrets/aws-access-key');
    expect(def.version).toBe('1');
    r.close();
    db.close();
  });

  it('mints a separate definition row per distinct ruleId', () => {
    const db = openLocalDatabase(dir);
    const ev = event({ kind: 'code_change', contentHash: 'hash-multi-rule' });
    db.recordCapture(ev, [
      finding({ ruleId: 'secrets/aws-access-key' }),
      finding({ ruleId: 'core-pii/email', category: 'pii', maskedMatch: 'j*@example.com' }),
    ]);

    const r = raw();
    expect(count(r, 'inspection_definitions')).toBe(2);
    expect(count(r, 'inspection_findings')).toBe(2);
    r.close();
    db.close();
  });
});
