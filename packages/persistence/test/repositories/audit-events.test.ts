import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LlmCallInput, ToolCallInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { llmCallId, toolCallId } from '../../src/ids.ts';

const SESSION_ID = 'session-audit-events-test';

let dir: string;
let db: ReturnType<typeof openLocalDatabase>;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-audit-events-'));
  db = openLocalDatabase(dir);
  // The leaves FK parent_id/root_session_id onto the session root, so seed it
  // the way the reconciler's ensure-root step does — through the shared seam.
  db.auditEvents.ensureSessionRoot(SESSION_ID, '2026-06-01T00:00:00.000Z');
});

afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
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
  });

  it('insertToolCall drops a leaf whose timestamp does not parse, keeping the rest of the batch', () => {
    db.auditEvents.runInTransaction(() => {
      db.auditEvents.insertToolCall(toolCall('toolu_good', '2026-06-01T01:00:00.000Z'));
      db.auditEvents.insertToolCall(toolCall('toolu_bad', '2026-13-99T99:99:99'));
    });

    expect(db.auditEvents.findById(toolCallId(SESSION_ID, 'toolu_good'))).toBeDefined();
    expect(db.auditEvents.findById(toolCallId(SESSION_ID, 'toolu_bad'))).toBeUndefined();
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
