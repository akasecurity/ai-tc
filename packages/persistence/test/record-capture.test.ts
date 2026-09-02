// recordCapture flipped from writing the legacy events/findings pair to
// writing the generalized audit_events/inspection_definitions/inspection_findings
// trio (see database.ts). These tests pin the NEW writer's behavior directly —
// the legacy events/findings tests in database.test.ts and the repository
// suites that read through them are EXPECTED to fail now that recordCapture no
// longer populates those tables; re-pointing those readers is a separate task.
import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { DetectedFindingWithKey, IngestEvent, LlmCallInput } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { schemaObjectExists } from '../src/db/migrations/introspection.ts';
import { captureId, llmCallId } from '../src/ids.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-record-capture-', { migrated: true });

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
  return store.openRaw();
}
function count(db: DatabaseSync, table: string): number {
  return (db.prepare(`SELECT count(*) AS n FROM ${table}`).get() as { n: number }).n;
}

describe('recordCapture — audit/inspection trio', () => {
  it('writes one audit_events row and one inspection_findings row wired to its definition', () => {
    const db = store.open();
    const ev = event({ kind: 'code_change', contentHash: 'hash-1' });
    db.recordCapture(ev, [finding()]);

    const auditEventId = captureId(null, 'hash-1');
    const r = raw();
    expect(count(r, 'audit_events')).toBe(1);
    expect(count(r, 'inspection_findings')).toBe(1);
    expect(count(r, 'inspection_definitions')).toBe(1);
    // The cutover is a full replacement, not a dual-write: `events`/`findings`
    // are not real tables at all — a fresh store drops them for the
    // compatibility views immediately (see migrations.ts's
    // applyLegacyDropMigration), so there is no separate legacy storage left
    // to duplicate into. Reading through the views still finds this same one
    // row (a truthful projection of the audit_events/inspection_findings
    // write above), not zero and not a second copy.
    expect(schemaObjectExists(r, 'table', 'events')).toBe(false);
    expect(schemaObjectExists(r, 'table', 'findings')).toBe(false);
    expect(count(r, 'events')).toBe(1);
    expect(count(r, 'findings')).toBe(1);

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
      const db = store.open();
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
    const db = store.open();
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
        inspectionMs: 7,
      },
    });
    db.recordCapture(ev, []);

    const auditEventId = captureId(sessionId, 'hash-attrs', 'src/index.ts');
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
      inspection_ms: 7,
    });
    // sessionId became the FK, never an attribute, under either casing.
    expect('sessionId' in attributes).toBe(false);
    expect('session_id' in attributes).toBe(false);
    r.close();
    db.close();
  });

  it('surfaces inspection_ms as a generated column, NULL when the capture carried no measurement', () => {
    const db = store.open();

    const measured = event({ kind: 'prompt', contentHash: 'hash-measured' });
    measured.metadata = { ...measured.metadata, inspectionMs: 0 };
    db.recordCapture(measured, []);

    const unmeasured = event({ kind: 'prompt', contentHash: 'hash-unmeasured' });
    db.recordCapture(unmeasured, []);

    const r = raw();
    const read = (id: string) =>
      (
        r.prepare('SELECT inspection_ms FROM audit_events WHERE id = ?').get(id) as {
          inspection_ms: number | null;
        }
      ).inspection_ms;

    // A measured 0 — a capture that finished inside a millisecond — must reach
    // the column as 0 and NOT as NULL: the read side computes a percentile over
    // the non-NULL rows, so collapsing the two would either drop a real sample
    // or invent one. `json_extract` returns SQL NULL for an absent key, which
    // is what makes the unmeasured row distinguishable at all.
    expect(read(captureId(null, 'hash-measured'))).toBe(0);
    expect(read(captureId(null, 'hash-unmeasured'))).toBeNull();
    r.close();
    db.close();
  });

  it('stamps parent_id/root_session_id to the session when present, NULL when absent', () => {
    const db = store.open();
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
    const db = store.open();
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
    const db = store.open();
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
    const db = store.open();
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
    const db = store.open();
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
    expect(row.audit_event_id).toBe(captureId(sessionId, 'hash-v2', 'src/config.ts')); // refreshed to latest capture
    expect(row.first_detected_at).toBe(new Date(first.occurredAt).getTime()); // preserved
    r.close();
    db.close();
  });

  it('an in-flight finding with no finding_key never collides across two captures', () => {
    const db = store.open();
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
    const db = store.open();
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
    // Version folds in the finding's classification (category/severity) so a
    // reclassification is not frozen out by the first-write-wins upsert.
    expect(def.version).toBe('capture/secret/critical');
    r.close();
    db.close();
  });

  it('mints a separate definition row per distinct ruleId', () => {
    const db = store.open();
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

  it('mints a new definition row when a pack update reclassifies a rule (severity change)', () => {
    const db = store.open();
    // Same ruleId + category, changed severity across two captures (a pack
    // update reclassifying high -> critical). Distinct contentHash so the audit
    // events differ; no sessionId so session dedup is skipped.
    db.recordCapture(event({ kind: 'code_change', contentHash: 'hash-low' }), [
      finding({ severity: 'low', maskedMatch: 'AKIA…LOW' }),
    ]);
    db.recordCapture(event({ kind: 'code_change', contentHash: 'hash-crit' }), [
      finding({ severity: 'critical', maskedMatch: 'AKIA…CRIT' }),
    ]);

    const r = raw();
    // A new definition row was minted rather than frozen at first-write.
    expect(
      (
        r
          .prepare('SELECT count(*) AS n FROM inspection_definitions WHERE rule_id = ?')
          .get('secrets/aws-access-key') as { n: number }
      ).n,
    ).toBe(2);
    // Reads take severity from the definition — each finding reflects the
    // classification it was captured under (history is not relabeled).
    const severityFor = (hash: string) =>
      (
        r
          .prepare(
            `SELECT d.severity AS severity FROM inspection_findings f
             JOIN inspection_definitions d ON d.id = f.inspection_definition_id
             JOIN audit_events e ON e.id = f.audit_event_id
            WHERE e.content_hash = ?`,
          )
          .get(hash) as { severity: string }
      ).severity;
    expect(severityFor('hash-crit')).toBe('critical');
    expect(severityFor('hash-low')).toBe('low');

    // Idempotent: re-detecting the SAME classification reuses the existing row.
    db.recordCapture(event({ kind: 'code_change', contentHash: 'hash-low-2' }), [
      finding({ severity: 'low', maskedMatch: 'AKIA…LOW2' }),
    ]);
    expect(
      (
        r
          .prepare('SELECT count(*) AS n FROM inspection_definitions WHERE rule_id = ?')
          .get('secrets/aws-access-key') as { n: number }
      ).n,
    ).toBe(2);
    r.close();
    db.close();
  });
});

// audit_events now mixes the four capture kinds with the transcript
// reconciler's structural `tool_call`/`llm_call` rows, all carrying the same
// `root_session_id`. The session-dedup that suppresses a value crossing several
// capture surfaces in one action must therefore constrain to capture kinds:
// otherwise a reconciler `tool_call` finding suppresses a later same-session
// capture, and — since the surviving `tool_call` row is excluded by every
// capture-kind read view — the finding disappears from the product entirely.
describe('recordCapture — session dedup is scoped to capture kinds', () => {
  const RULE = 'secrets/aws-access-key';

  it('does NOT let a reconciler tool_call finding suppress a same-session capture', () => {
    const db = store.open();
    const sessionId = randomUUID();
    const started = new Date().toISOString();

    // Session root (self-FK target for the session-scoped rows below).
    db.auditEvents.insertAuditEvent({ id: sessionId, eventType: 'session', startedAt: started });

    // A transcript-reconciler finding for (rule, masked value) on a NON-capture
    // `tool_call` audit event in this session.
    const toolCallEventId = randomUUID();
    db.auditEvents.insertAuditEvent({
      id: toolCallEventId,
      eventType: 'tool_call',
      startedAt: started,
      parentId: sessionId,
      rootSessionId: sessionId,
    });
    const defId = db.inspectionDefinitions.upsert({
      ruleId: RULE,
      version: 'transcript-1',
      name: RULE,
      category: 'secret',
      severity: 'critical',
      definition: '{}',
    });
    db.inspectionFindings.insertFinding({
      id: randomUUID(),
      auditEventId: toolCallEventId,
      inspectionDefinitionId: defId,
      span: { start: 0, end: 20 },
      maskedMatch: MASKED,
      actionTaken: 'block',
      confidence: 0.9,
    });

    // The user then writes that same secret to a file in the same session.
    const ev = event({
      kind: 'code_change',
      contentHash: 'hash-live-capture',
      metadata: { sessionId },
    });
    db.recordCapture(ev, [finding({ ruleId: RULE, maskedMatch: MASKED })]);

    const r = raw();
    // The live capture's finding survived and is attached to a code_change row.
    const onCapture = r
      .prepare(
        `SELECT count(*) AS n FROM inspection_findings f
           JOIN audit_events e ON e.id = f.audit_event_id
          WHERE f.masked_match = ? AND e.event_type = 'code_change'`,
      )
      .get(MASKED) as { n: number };
    expect(onCapture.n).toBe(1);
    // Both rows coexist: the reconciler's tool_call one and the live capture.
    const total = r
      .prepare('SELECT count(*) AS n FROM inspection_findings WHERE masked_match = ?')
      .get(MASKED) as { n: number };
    expect(total.n).toBe(2);
    r.close();
    db.close();
  });

  it('still suppresses the same value crossing two capture surfaces in one session', () => {
    const db = store.open();
    const sessionId = randomUUID();

    // Same (rule, masked value) captured first on a prompt, then a tool_use, in
    // one session — the legitimate cross-surface dedup the guard must preserve.
    const p = event({ kind: 'prompt', contentHash: 'hash-prompt-dup', metadata: { sessionId } });
    db.recordCapture(p, [finding({ ruleId: RULE, maskedMatch: MASKED })]);
    const t = event({ kind: 'tool_use', contentHash: 'hash-tooluse-dup', metadata: { sessionId } });
    db.recordCapture(t, [finding({ ruleId: RULE, maskedMatch: MASKED })]);

    const r = raw();
    const total = r
      .prepare('SELECT count(*) AS n FROM inspection_findings WHERE masked_match = ?')
      .get(MASKED) as { n: number };
    expect(total.n).toBe(1); // deduped across capture surfaces
    r.close();
    db.close();
  });
});

// captureId folds the file path into the audit-event identity, so two DISTINCT
// at-rest files with byte-identical content stay two rows. Without it, the
// second file's audit event collapses onto the first (INSERT OR IGNORE) and its
// finding is skipped by the event-scoped dedup — a silent secret under-report.
describe('recordCapture — at-rest path disambiguation', () => {
  it('keeps two identical-content files as two findings with two finding_keys', () => {
    const db = store.open();
    // No sessionId, so session dedup is out of the way; identical content, same
    // rule/span/mask — only the path differs.
    const a = event({
      kind: 'code_change',
      contentHash: 'hash-identical',
      content: 'k <redacted>',
      metadata: { filePath: 'src/a.ts' },
    });
    const b = event({
      kind: 'code_change',
      contentHash: 'hash-identical',
      content: 'k <redacted>',
      metadata: { filePath: 'src/b.ts' },
    });
    db.recordCapture(a, [finding({ findingKey: 'fk-a' })]);
    db.recordCapture(b, [finding({ findingKey: 'fk-b' })]);

    expect(captureId(null, 'hash-identical', 'src/a.ts')).not.toBe(
      captureId(null, 'hash-identical', 'src/b.ts'),
    );

    const r = raw();
    expect(count(r, 'audit_events')).toBe(2);
    expect(count(r, 'inspection_findings')).toBe(2);
    const keys = (
      r.prepare('SELECT finding_key FROM inspection_findings ORDER BY finding_key').all() as {
        finding_key: string;
      }[]
    ).map((row) => row.finding_key);
    expect(keys).toEqual(['fk-a', 'fk-b']);
    // Each finding is attached to its OWN file's audit event.
    const idA = captureId(null, 'hash-identical', 'src/a.ts');
    const attachedToA = r
      .prepare('SELECT finding_key FROM inspection_findings WHERE audit_event_id = ?')
      .get(idA) as { finding_key: string };
    expect(attachedToA.finding_key).toBe('fk-a');
    r.close();
    db.close();
  });

  it('still collapses a re-scan of the SAME file (path+content stable) onto one row', () => {
    const db = store.open();
    const ev = () =>
      event({
        kind: 'code_change',
        contentHash: 'hash-same',
        content: 'k <redacted>',
        metadata: { filePath: 'src/same.ts' },
      });
    db.recordCapture(ev(), [finding({ findingKey: 'fk-same' })]);
    db.recordCapture(ev(), [finding({ findingKey: 'fk-same' })]);

    const r = raw();
    expect(count(r, 'audit_events')).toBe(1);
    expect(count(r, 'inspection_findings')).toBe(1);
    r.close();
    db.close();
  });

  it('path-less in-flight captures with identical content still collapse (NO_PATH)', () => {
    const db = store.open();
    const sessionId = randomUUID();
    const p1 = event({ kind: 'prompt', contentHash: 'hash-pl', metadata: { sessionId } });
    const p2 = event({ kind: 'prompt', contentHash: 'hash-pl', metadata: { sessionId } });
    db.recordCapture(p1, []);
    db.recordCapture(p2, []);

    const r = raw();
    expect(count(r, 'audit_events')).toBe(2); // session root stub + the one collapsed prompt
    expect(
      (
        r.prepare("SELECT count(*) AS n FROM audit_events WHERE event_type='prompt'").get() as {
          n: number;
        }
      ).n,
    ).toBe(1);
    r.close();
    db.close();
  });
});

// The STRUCTURAL half of the same seam. Kept beside markCaptureDelivered
// deliberately: the two stamps share one column across two disjoint drains, and
// the boundary between them is only testable where both are in view.
describe('markAuditEventsDelivered', () => {
  const syncedAt = (db: DatabaseSync, id: string): number | null =>
    (
      db.prepare(`SELECT synced_at AS s FROM audit_events WHERE id = ?`).get(id) as {
        s: number | null;
      }
    ).s;

  const llmCall = (sessionId: string, messageId: string): LlmCallInput => ({
    sessionId,
    messageId,
    parentId: sessionId,
    rootSessionId: sessionId,
    startedAt: '2026-01-01T00:00:00.000Z',
    attributes: { model: 'claude-opus-5', provider: 'anthropic' },
  });

  it('stamps the row insertLlmCall wrote, found by the same derivation', () => {
    // THE PREMISE THE WHOLE FEATURE RESTS ON, and the only place it is executed
    // against a real row. The attached gateway builds the forwarded event's id
    // with `llmCallId(sessionId, messageId)`; `insertLlmCall` derives the local
    // primary key from the same function. If those ever diverge the UPDATE
    // matches nothing — and a SQLite UPDATE matching no rows is not an error, so
    // every fake-backed suite would stay green while the outbox silently went on
    // over-counting. Derived here rather than read back from the insert, so a
    // change to either side fails HERE.
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-llm', '2026-01-01T00:00:00.000Z');
    db.auditEvents.insertLlmCall(llmCall('s-llm', 'm-1'));
    const id = llmCallId('s-llm', 'm-1');

    expect(syncedAt(raw(), id)).toBeNull();
    db.markAuditEventsDelivered(
      [{ id, eventType: 'llm_call', startedAt: '2026-01-01T00:00:00.000Z' }],
      1_700_000_000_000,
    );
    expect(syncedAt(raw(), id)).toBe(1_700_000_000_000);
  });

  it('leaves every other structural row outstanding', () => {
    // Scoped to the events handed in, not the session: a batch whose head landed
    // and whose tail the budget dropped must stamp only the head.
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-batch', '2026-01-01T00:00:00.000Z');
    db.auditEvents.insertLlmCall(llmCall('s-batch', 'm-a'));
    db.auditEvents.insertLlmCall(llmCall('s-batch', 'm-b'));

    db.markAuditEventsDelivered(
      [
        {
          id: llmCallId('s-batch', 'm-a'),
          eventType: 'llm_call',
          startedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      1_700_000_000_000,
    );
    expect(syncedAt(raw(), llmCallId('s-batch', 'm-a'))).toBe(1_700_000_000_000);
    expect(syncedAt(raw(), llmCallId('s-batch', 'm-b'))).toBeNull();
  });

  it('moves the row out of `queued` and into `synced` in the partition', () => {
    // The read this exists to make honest. Asserted through partition() rather
    // than through the column, because the column being set is not the claim —
    // the claim is that the bucket a surface renders actually moves.
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-part', '2026-01-01T00:00:00.000Z');
    db.auditEvents.insertLlmCall(llmCall('s-part', 'm-1'));
    // The session root is structural too, so it is counted alongside the leaf.
    expect(db.historySync.partition()).toMatchObject({ queued: 2, synced: 0 });

    db.markAuditEventsDelivered(
      [
        {
          id: llmCallId('s-part', 'm-1'),
          eventType: 'llm_call',
          startedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      1_700_000_000_000,
    );
    expect(db.historySync.partition()).toMatchObject({ queued: 1, synced: 1 });
  });

  it('REFUSES a capture-grain row, leaving it for the capture drain', () => {
    // The lane boundary, and the reason this method filters at all.
    // `recordAuditEvent` accepts any AuditEventType, so a capture routed through
    // it would otherwise be stamped on a forward that carried no `content` — and
    // `pendingCaptureRows` filters `synced_at IS NULL`, so the capture drain
    // would never offer that row again. Silent, permanent loss of the text.
    const db = store.open();
    const ev = event({ metadata: { sessionId: 's-cap' }, contentHash: 'hash-cap' });
    db.recordCapture(ev, []);
    const id = captureId('s-cap', 'hash-cap', null);

    db.markAuditEventsDelivered(
      [{ id, eventType: 'prompt', startedAt: '2026-01-01T00:00:00.000Z' }],
      1_700_000_000_000,
    );
    expect(syncedAt(raw(), id)).toBeNull();
  });

  it('stamps the structural rows of a MIXED batch and refuses the capture ones', () => {
    // The partial case the filter has to get right: an all-capture batch is
    // caught by the early return, so only a mixed one drives the predicate.
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-mix', '2026-01-01T00:00:00.000Z');
    db.auditEvents.insertLlmCall(llmCall('s-mix', 'm-1'));
    const cap = event({ metadata: { sessionId: 's-mix' }, contentHash: 'hash-mix' });
    db.recordCapture(cap, []);

    db.markAuditEventsDelivered(
      [
        {
          id: llmCallId('s-mix', 'm-1'),
          eventType: 'llm_call',
          startedAt: '2026-01-01T00:00:00.000Z',
        },
        {
          id: captureId('s-mix', 'hash-mix', null),
          eventType: 'prompt',
          startedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
      1_700_000_000_000,
    );
    expect(syncedAt(raw(), llmCallId('s-mix', 'm-1'))).toBe(1_700_000_000_000);
    expect(syncedAt(raw(), captureId('s-mix', 'hash-mix', null))).toBeNull();
  });
});

// The live forward's half of the outbox: a delivered capture is stamped, an
// undelivered one is not, and "not stamped" is what makes a row outstanding.
describe('markCaptureDelivered', () => {
  const syncedAt = (db: DatabaseSync, id: string): number | null =>
    (
      db.prepare(`SELECT synced_at AS s FROM audit_events WHERE id = ?`).get(id) as {
        s: number | null;
      }
    ).s;

  it('stamps the row recordCapture wrote, found by the same tuple', () => {
    // The join the whole design rests on: the stamp has to land on the row the
    // write created. Derived here from the tuple rather than read back from the
    // insert, so a change to either derivation fails this instead of silently
    // stamping nothing — an UPDATE that matches no row reports success.
    const db = store.open();
    const ev = event({ metadata: { sessionId: 's-1' }, contentHash: 'hash-live' });
    db.recordCapture(ev, []);
    const id = captureId('s-1', 'hash-live', null);

    expect(syncedAt(raw(), id)).toBeNull();
    db.markCaptureDelivered(ev, 1_700_000_000_000);
    expect(syncedAt(raw(), id)).toBe(1_700_000_000_000);
  });

  it('leaves every other capture outstanding', () => {
    // Scoped to the one event, not the session and not the store: two prompts
    // in one session are two deliveries, and stamping a batch because one of
    // them landed is how an outbox loses events.
    const db = store.open();
    const delivered = event({ metadata: { sessionId: 's-2' }, contentHash: 'hash-a' });
    const outstanding = event({ metadata: { sessionId: 's-2' }, contentHash: 'hash-b' });
    db.recordCapture(delivered, []);
    db.recordCapture(outstanding, []);

    db.markCaptureDelivered(delivered, 1_700_000_000_000);
    expect(syncedAt(raw(), captureId('s-2', 'hash-a', null))).toBe(1_700_000_000_000);
    expect(syncedAt(raw(), captureId('s-2', 'hash-b', null))).toBeNull();
  });

  it('is fail-open on a capture that was never written', () => {
    // A stamp for a row that does not exist must not throw: the forward already
    // succeeded, the session is live, and there is nothing left to salvage by
    // raising here.
    const db = store.open();
    expect(() => {
      db.markCaptureDelivered(event({ contentHash: 'never-stored' }), 1);
    }).not.toThrow();
  });
});
