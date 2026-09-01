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
    // started_at takes the EARLIER of the two. The heal systematically arrives
    // later than the stub it fills — the reconciler anchors on the first
    // ASSISTANT record, which follows the prompt capture that planted the stub —
    // so replacing would push the root past its own first child every time.
    expect(row?.started_at).toBe(Date.parse('2026-06-02T00:00:00.000Z'));
  });

  it('a heal that is EARLIER than the stub still moves started_at back', () => {
    // The control for the case above: min() is taking the earlier value, not
    // merely refusing to write. A stub planted by a capture can legitimately be
    // later than the authoritative start when SessionStart's own write is what
    // landed second.
    db.auditEvents.ensureSessionRoot('s-heal-earlier', '2026-06-02T00:00:05.000Z');
    db.auditEvents.insertAuditEvent({
      id: 's-heal-earlier',
      eventType: 'session',
      startedAt: '2026-06-02T00:00:00.000Z',
      attributes: { harness: 'claudecode' },
    });

    const row = db.auditEvents.findById('s-heal-earlier');
    expect(row?.attributes ?? '').toContain('claudecode');
    expect(row?.started_at).toBe(Date.parse('2026-06-02T00:00:00.000Z'));
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

    const leaf = db.auditEvents.findById(llmCallId('s-heal-fk', 'm1'));
    const root = db.auditEvents.findById('s-heal-fk');
    if (leaf === undefined || root === undefined) throw new Error('expected both rows');
    expect(root.attributes ?? '').toContain('claudecode');
    // A root never starts after a descendant that already FKs onto it. The heal
    // carries a LATER timestamp (00:00:05) than the leaf recorded against the
    // stub (00:00:01), so this is exactly the case a straight replace breaks.
    expect(root.started_at).toBeLessThanOrEqual(leaf.started_at);
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

  it('a second stub never moves an existing stub, in EITHER direction', () => {
    db.auditEvents.ensureSessionRoot('s-two-stubs', '2026-06-02T00:00:00.000Z');
    db.auditEvents.ensureSessionRoot('s-two-stubs', '2030-01-01T00:00:00.000Z');

    expect(db.auditEvents.findById('s-two-stubs')?.started_at).toBe(
      Date.parse('2026-06-02T00:00:00.000Z'),
    );

    // And not earlier either. `ensureSessionRoot` runs on EVERY capture, so this
    // is the hot path: `excluded.attributes IS NOT NULL` is what keeps a stub a
    // pure no-op against a stored row rather than an UPDATE per capture. Without
    // that clause min() would quietly pull the row back here — cheaper to leave
    // a placeholder alone, since the heal replaces it with a real value anyway.
    db.auditEvents.ensureSessionRoot('s-two-stubs', '2020-01-01T00:00:00.000Z');
    expect(db.auditEvents.findById('s-two-stubs')?.started_at).toBe(
      Date.parse('2026-06-02T00:00:00.000Z'),
    );
  });

  it('an unparseable startedAt drops the row rather than throwing', () => {
    // `started_at` is NOT NULL and isoToEpochMillis yields NaN here, which
    // node:sqlite binds as NULL. The write path has always dropped such a row
    // silently; routing session roots through an UPSERT must not turn that into
    // a throw, because neither reconcile caller catches — one poisoned session
    // would abandon the rest of a backfill walk, and a tail pass would never
    // advance its offset and would re-throw on the same bytes for ever.
    expect(() => {
      db.auditEvents.insertAuditEvent({
        id: 's-nan',
        eventType: 'session',
        startedAt: 'not-a-date',
      });
    }).not.toThrow();
    expect(db.auditEvents.findById('s-nan')).toBeUndefined();

    // Control: a non-session row carries the SAME bad timestamp down the other
    // statement, so a failure above is the session-root routing and not the
    // fixture.
    expect(() => {
      db.auditEvents.insertAuditEvent({
        id: 'e-nan',
        eventType: 'prompt',
        startedAt: 'not-a-date',
      });
    }).not.toThrow();
    expect(db.auditEvents.findById('e-nan')).toBeUndefined();
  });

  it('an unparseable startedAt never damages a root already stored', () => {
    db.auditEvents.insertAuditEvent({
      id: 's-nan-heal',
      eventType: 'session',
      startedAt: '2026-06-01T00:00:00.000Z',
      attributes: { harness: 'claudecode' },
    });
    expect(() => {
      db.auditEvents.insertAuditEvent({
        id: 's-nan-heal',
        eventType: 'session',
        startedAt: 'not-a-date',
        attributes: { harness: 'codex' },
      });
    }).not.toThrow();

    const row = db.auditEvents.findById('s-nan-heal');
    expect(row?.started_at).toBe(Date.parse('2026-06-01T00:00:00.000Z'));
    expect(row?.attributes ?? '').toContain('claudecode');
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
