import type { LlmCallInput, ToolCallInput } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { llmCallId, toolCallId } from '../../src/ids.ts';
import { useTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';

const SESSION_ID = 'session-audit-events-test';

const store = useTempStore('aka-audit-events-');
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
