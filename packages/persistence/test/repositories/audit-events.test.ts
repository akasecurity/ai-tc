import type { LlmCallInput, ToolCallInput } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { llmCallId, toolCallId } from '../../src/ids.ts';
import { useTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';

const SESSION_ID = 'session-audit-events-test';

const store = useTempStore('aka-audit-events-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
  // The leaves FK parent_id/root_session_id onto the session root, so seed it
  // the way the reconciler's ensure-root step does — through the shared seam.
  db.auditEvents.ensureSessionRoot(SESSION_ID, '2026-06-01T00:00:00.000Z');
});

function llmCall(messageId: string, startedAt: string): LlmCallInput {
  return {
    sessionId: SESSION_ID,
    messageId,
    parentId: SESSION_ID,
    rootSessionId: SESSION_ID,
    startedAt,
    attributes: { output_tokens: 10 },
  };
}

function toolCall(toolUseId: string, startedAt: string): ToolCallInput {
  return {
    sessionId: SESSION_ID,
    toolUseId,
    parentId: SESSION_ID,
    rootSessionId: SESSION_ID,
    startedAt,
    attributes: { tool_name: 'Bash' },
    inspections: [],
  };
}

// One transcript record with a present-but-unparseable timestamp must not sink
// the whole reconcile pass: isoToEpochMillis returns NaN for it, NaN binds as
// NULL into the NOT NULL started_at column, and the resulting throw inside the
// single-transaction pass would roll back every leaf — permanently, since the
// malformed record stays in the transcript and re-fails every later pass. The
// repository drops just the bad leaf instead.
describe('malformed startedAt tolerance', () => {
  it('insertLlmCall drops a leaf whose timestamp does not parse, keeping the rest of the batch', () => {
    db.auditEvents.runInTransaction(() => {
      db.auditEvents.insertLlmCall(llmCall('msg_good_1', '2026-06-01T01:00:00.000Z'));
      db.auditEvents.insertLlmCall(llmCall('msg_bad', 'not-a-timestamp'));
      db.auditEvents.insertLlmCall(llmCall('msg_good_2', '2026-06-01T02:00:00.000Z'));
    });

    expect(db.auditEvents.findById(llmCallId(SESSION_ID, 'msg_good_1'))).toBeDefined();
    expect(db.auditEvents.findById(llmCallId(SESSION_ID, 'msg_bad'))).toBeUndefined();
    expect(db.auditEvents.findById(llmCallId(SESSION_ID, 'msg_good_2'))).toBeDefined();
    // Dropping the bad leaf must also close the transaction it was dropped
    // inside. A pass that swallowed the malformed row but returned still inside
    // its BEGIN would leave every later write on this handle joining it, which
    // reads as a healthy store right up to the point nothing is durable.
    assertNoOpenTransaction(db[UNSAFE_TEST_ONLY_RAW_HANDLE]);
  });

  it('insertToolCall drops a leaf whose timestamp does not parse, keeping the rest of the batch', () => {
    db.auditEvents.runInTransaction(() => {
      db.auditEvents.insertToolCall(toolCall('toolu_good', '2026-06-01T01:00:00.000Z'));
      db.auditEvents.insertToolCall(toolCall('toolu_bad', '2026-13-99T99:99:99'));
    });

    expect(db.auditEvents.findById(toolCallId(SESSION_ID, 'toolu_good'))).toBeDefined();
    expect(db.auditEvents.findById(toolCallId(SESSION_ID, 'toolu_bad'))).toBeUndefined();
    // Asserted on BOTH arms, not just the llm_call one above: the two insert
    // paths drop a malformed leaf independently, so a containment check on one
    // leaves the other free to strand a transaction and stay green.
    assertNoOpenTransaction(db[UNSAFE_TEST_ONLY_RAW_HANDLE]);
  });

  it('a valid leaf still lands with its parsed epoch-millis started_at', () => {
    db.auditEvents.insertLlmCall(llmCall('msg_ts', '2026-06-01T03:00:00.000Z'));
    const row = db.auditEvents.findById(llmCallId(SESSION_ID, 'msg_ts'));
    expect(row?.started_at).toBe(Date.parse('2026-06-01T03:00:00.000Z'));
  });
});

describe('ensureSessionRoot', () => {
  it('plants a root a session-scoped leaf can FK onto', () => {
    // A session distinct from the beforeEach seed, with no root yet.
    db.auditEvents.ensureSessionRoot('s-new', '2026-06-02T00:00:00.000Z');
    expect(() => {
      db.auditEvents.insertLlmCall({
        sessionId: 's-new',
        messageId: 'm1',
        parentId: 's-new',
        rootSessionId: 's-new',
        startedAt: '2026-06-02T00:00:01.000Z',
        attributes: { output_tokens: 5 },
      });
    }).not.toThrow();
    // The FK resolved: the leaf actually persisted.
    expect(db.auditEvents.findById(llmCallId('s-new', 'm1'))).toBeDefined();
    const root = db.auditEvents.findById('s-new');
    expect(root?.event_type).toBe('session');
  });

  it('an authoritative root arriving after the stub HEALS it in place', () => {
    // The regression: a session-scoped leaf lands before SessionStart's root,
    // so `ensureSessionRoot` stubs the row with no dimensions and no attributes.
    db.auditEvents.ensureSessionRoot('s-heal', '2026-06-02T00:00:00.000Z');
    expect(db.auditEvents.findById('s-heal')?.attributes).toBeNull();

    // SessionStart (or the reconciler's buildSessionRoot) then writes the real
    // root on the same id. Under the old INSERT OR IGNORE this was silently
    // dropped and the session kept empty attributes forever — no `harness`, so
    // every read grouping on it mis-bucketed the whole session.
    db.auditEvents.insertAuditEvent({
      id: 's-heal',
      eventType: 'session',
      startedAt: '2026-06-02T00:00:05.000Z',
      attributes: { harness: 'claudecode', provider: 'anthropic' },
    });

    const row = db.auditEvents.findById('s-heal');
    expect(row?.attributes ?? '').toContain('claudecode');
    expect(db.auditEvents.sessionProvider('s-heal')).toBe('anthropic');
    // started_at is replaced too: the stub's value was a capture's timestamp
    // standing in for a session start nobody had recorded.
    expect(row?.started_at).toBe(Date.parse('2026-06-02T00:00:05.000Z'));
  });

  it('the heal keeps the leaves that FK onto the stub attached to the root', () => {
    db.auditEvents.ensureSessionRoot('s-heal-fk', '2026-06-02T00:00:00.000Z');
    db.auditEvents.insertLlmCall({
      sessionId: 's-heal-fk',
      messageId: 'm1',
      parentId: 's-heal-fk',
      rootSessionId: 's-heal-fk',
      startedAt: '2026-06-02T00:00:01.000Z',
      attributes: { output_tokens: 7 },
    });

    // An UPDATE on the PK's row (not a delete+insert) — the self-FK holds.
    expect(() => {
      db.auditEvents.insertAuditEvent({
        id: 's-heal-fk',
        eventType: 'session',
        startedAt: '2026-06-02T00:00:05.000Z',
        attributes: { harness: 'claudecode' },
      });
    }).not.toThrow();

    expect(db.auditEvents.findById(llmCallId('s-heal-fk', 'm1'))).toBeDefined();
    expect(db.auditEvents.findById('s-heal-fk')?.attributes ?? '').toContain('claudecode');
  });

  it('two authoritative roots stay first-write-wins — the second never rewrites the first', () => {
    // SessionStart's contemporaneous env-provider must beat the reconciler's
    // model-id heuristic (plugins/*/src/history/usage.ts reads it back off the
    // root and denormalizes it onto every llm_call leaf).
    db.auditEvents.insertAuditEvent({
      id: 's-two-roots',
      eventType: 'session',
      startedAt: '2026-06-01T00:00:00.000Z',
      attributes: { provider: 'bedrock', harness: 'claudecode' },
    });
    db.auditEvents.insertAuditEvent({
      id: 's-two-roots',
      eventType: 'session',
      startedAt: '2026-06-01T00:00:10.000Z',
      attributes: { provider: 'unknown', harness: 'claudecode' },
    });

    expect(db.auditEvents.sessionProvider('s-two-roots')).toBe('bedrock');
    expect(db.auditEvents.findById('s-two-roots')?.started_at).toBe(
      Date.parse('2026-06-01T00:00:00.000Z'),
    );
  });

  it('a second stub never pushes an existing stub\'s started_at later', () => {
    db.auditEvents.ensureSessionRoot('s-two-stubs', '2026-06-02T00:00:00.000Z');
    db.auditEvents.ensureSessionRoot('s-two-stubs', '2030-01-01T00:00:00.000Z');

    expect(db.auditEvents.findById('s-two-stubs')?.started_at).toBe(
      Date.parse('2026-06-02T00:00:00.000Z'),
    );
  });

  it('is first-write-wins and never clobbers an authoritative root', () => {
    // A rich, authoritative root arrives first (dimensions + a later timeline).
    db.auditEvents.insertAuditEvent({
      id: 's-rich',
      eventType: 'session',
      startedAt: '2026-06-01T00:00:00.000Z',
      attributes: { provider: 'demo' },
    });
    // A later stub must be a no-op — not overwrite started_at nor drop attributes.
    db.auditEvents.ensureSessionRoot('s-rich', '2030-01-01T00:00:00.000Z');

    const row = db.auditEvents.findById('s-rich');
    expect(row?.started_at).toBe(Date.parse('2026-06-01T00:00:00.000Z'));
    expect(row?.attributes ?? '').toContain('demo');
  });
});
