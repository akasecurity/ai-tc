import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-history-sync-');

const T0 = Date.parse('2026-08-01T00:00:00.000Z');
const at = (offsetMs: number): string => new Date(T0 + offsetMs).toISOString();
const MINUTE = 60_000;

// Past every seeded row, so the existing cases keep testing the ledger rather
// than the boundary; the cutoff has its own block at the end.
const ALL = T0 + 365 * 24 * 60 * 60 * 1000;

/** A session root and a structural leaf under it, plus a capture leaf. */
function seedSession(db: LocalDatabase, sessionId: string, offsetMs: number): void {
  db.auditEvents.ensureSessionRoot(sessionId, at(offsetMs));
  db.auditEvents.insertAuditEvent({
    id: `${sessionId}-llm`,
    eventType: 'llm_call',
    rootSessionId: sessionId,
    parentId: sessionId,
    startedAt: at(offsetMs + MINUTE),
  });
  db.auditEvents.insertAuditEvent({
    id: `${sessionId}-tool`,
    eventType: 'tool_call',
    rootSessionId: sessionId,
    parentId: sessionId,
    startedAt: at(offsetMs + 2 * MINUTE),
  });
  // A capture: this lane must never pick it up.
  db.auditEvents.insertAuditEvent({
    id: `${sessionId}-prompt`,
    eventType: 'prompt',
    rootSessionId: sessionId,
    parentId: sessionId,
    startedAt: at(offsetMs + 3 * MINUTE),
    content: 'the text of a prompt',
  });
}

describe('SqliteHistorySyncRepository — what is pending', () => {
  it('offers sessions oldest first', () => {
    const db = store.open();
    seedSession(db, 's-late', 10 * MINUTE);
    seedSession(db, 's-early', 0);

    expect(db.historySync.pendingSessions(10, ALL)).toEqual(['s-early', 's-late']);
  });

  // The whole scope of the feature: prompts and replies are not in this lane,
  // and no filter someone widens by accident can put them there.
  it('never offers a capture row', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);

    const ids = db.historySync.pendingRows('s-1', 100, ALL).map((r) => r.id);
    expect(ids).not.toContain('s-1-prompt');
    expect(ids).toEqual(['s-1', 's-1-llm', 's-1-tool']);
  });

  // Root first is not cosmetic: the receiving side has real self-referencing
  // foreign keys and stubs nothing, so a leaf that lands first is rejected.
  it('puts the session root before its leaves, whatever their times', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(99 * MINUTE));
    db.auditEvents.insertAuditEvent({
      id: 'leaf',
      eventType: 'llm_call',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(0),
    });

    expect(db.historySync.pendingRows('s-1', 10, ALL)[0]?.id).toBe('s-1');
  });

  // A session whose root already went but whose leaves did not is still work.
  it('still offers a session once only its root has been sent', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1'], T0);

    expect(db.historySync.pendingSessions(10, ALL)).toEqual(['s-1']);
    expect(db.historySync.pendingRows('s-1', 10, ALL).map((r) => r.id)).toEqual([
      's-1-llm',
      's-1-tool',
    ]);
  });

  it('offers nothing once everything structural has been sent', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1', 's-1-llm', 's-1-tool'], T0);

    expect(db.historySync.pendingSessions(10, ALL)).toEqual([]);
  });

  it('honours the limit', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    seedSession(db, 's-2', MINUTE);

    expect(db.historySync.pendingSessions(1, ALL)).toHaveLength(1);
    expect(db.historySync.pendingRows('s-1', 2, ALL)).toHaveLength(2);
  });
});

describe('SqliteHistorySyncRepository — counting', () => {
  it('counts only structural rows, split by what happened to them', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1'], T0);
    db.historySync.markSkipped(['s-1-llm']);

    // The capture row is in neither total.
    expect(db.historySync.counts(ALL)).toEqual({ pending: 1, sent: 1, skipped: 1 });
  });

  it('counts an empty store as nothing rather than throwing', () => {
    const db = store.open();
    expect(db.historySync.counts(ALL)).toEqual({ pending: 0, sent: 0, skipped: 0 });
  });

  // A skip is for a row that cannot be rebuilt. It must not be retried, or the
  // drain loops on it for ever.
  it('does not offer a skipped row again', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSkipped(['s-1', 's-1-llm', 's-1-tool']);

    expect(db.historySync.pendingSessions(10, ALL)).toEqual([]);
  });

  it('stamps nothing when given no ids', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced([], T0);

    expect(db.historySync.counts(ALL).pending).toBe(3);
  });
});

describe('SqliteHistorySyncRepository — which deployment the stamps are for', () => {
  it('has no fingerprint until one is recorded', () => {
    const db = store.open();
    expect(db.historySync.deployment().fingerprint).toBeUndefined();
  });

  // Delivery is a fact about one recipient. Rows sent to a deployment this
  // machine has left are undelivered as far as the next one is concerned.
  it('re-arms delivered rows when the deployment changes', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markSynced(['s-1', 's-1-llm', 's-1-tool'], T0);
    expect(db.historySync.counts(ALL)).toMatchObject({ pending: 0, sent: 3 });

    db.historySync.rearmFor('fingerprint-b', ALL);

    expect(db.historySync.deployment().fingerprint).toBe('fingerprint-b');
    expect(db.historySync.counts(ALL)).toMatchObject({ pending: 3, sent: 0 });
  });

  // A row that could not be rebuilt locally fails the same way anywhere, so
  // pointing at a new deployment must not resurrect it.
  it('leaves permanently skipped rows skipped across a change of deployment', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSkipped(['s-1-llm']);
    db.historySync.rearmFor('fingerprint-b', ALL);

    expect(db.historySync.counts(ALL).skipped).toBe(1);
  });
});

describe('SqliteHistorySyncRepository — the claim', () => {
  const STALE = 60_000;

  it('is free to take on an untouched store', () => {
    const db = store.open();
    expect(db.historySync.claim(101, 'host-a', T0, STALE)).toBe(true);
    expect(db.historySync.lease()).toMatchObject({ ownerPid: 101, ownerHost: 'host-a' });
  });

  it('refuses a second live holder', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);

    expect(db.historySync.claim(202, 'host-b', T0 + 1_000, STALE)).toBe(false);
    expect(db.historySync.lease()?.ownerPid).toBe(101);
  });

  it('is takeable once the holder has stopped saying it is alive', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);

    expect(db.historySync.claim(202, 'host-b', T0 + STALE + 1, STALE)).toBe(true);
    expect(db.historySync.lease()?.ownerPid).toBe(202);
  });

  // A backwards clock correction would otherwise strand the claim until the
  // clock caught up — on a large correction, indistinguishable from never.
  it('treats a heartbeat stamped in the future as stale', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0 + 10 * MINUTE, STALE);

    expect(db.historySync.claim(202, 'host-b', T0, STALE)).toBe(true);
  });

  it('keeps a live holder alive on a heartbeat', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);
    db.historySync.heartbeat(101, T0 + STALE);

    expect(db.historySync.claim(202, 'host-b', T0 + STALE + 1, STALE)).toBe(false);
  });

  it('ignores a heartbeat from a process that no longer holds it', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);
    db.historySync.claim(202, 'host-b', T0 + STALE + 1, STALE);
    db.historySync.heartbeat(101, T0 + 10 * MINUTE);

    expect(db.historySync.lease()?.ownerPid).toBe(202);
  });

  it('frees the claim on release', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);
    db.historySync.release(101);

    expect(db.historySync.lease()?.ownerPid).toBeNull();
    expect(db.historySync.claim(202, 'host-b', T0 + 1, STALE)).toBe(true);
  });

  // Releasing a claim someone else has taken over would hand it to a third
  // process while the second was still working.
  it('does not let a superseded holder release the new one', () => {
    const db = store.open();
    db.historySync.claim(101, 'host-a', T0, STALE);
    db.historySync.claim(202, 'host-b', T0 + STALE + 1, STALE);
    db.historySync.release(101);

    expect(db.historySync.lease()?.ownerPid).toBe(202);
  });
});

describe('SqliteHistorySyncRepository — the backlog boundary', () => {
  // The drain exists for what was recorded BEFORE the machine attached.
  // Everything after is the live forward path's to deliver, and it delivers it
  // with the deployment's own inventory ids substituted in — so a drain that
  // also sent those rows would duplicate every one of them, and re-posting a
  // session root (an UPDATE, not a no-op) would overwrite those resolved ids
  // with nothing.
  it('offers nothing recorded at or after the boundary', () => {
    const db = store.open();
    seedSession(db, 's-after', 10 * MINUTE);

    expect(db.historySync.pendingSessions(10, T0 + 5 * MINUTE)).toEqual([]);
  });

  it('offers what was recorded before it', () => {
    const db = store.open();
    seedSession(db, 's-before', 0);
    seedSession(db, 's-after', 10 * MINUTE);

    expect(db.historySync.pendingSessions(10, T0 + 5 * MINUTE)).toEqual(['s-before']);
  });

  // A session straddling the boundary must not have its later leaves sent: the
  // live path owns those, and the root is what carries the inventory join.
  it('stops at the boundary inside one session', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);

    const ids = db.historySync.pendingRows('s-1', 100, T0 + 90_000).map((r) => r.id);
    expect(ids).toEqual(['s-1', 's-1-llm']);
  });

  it('counts only what is inside the backlog as pending', () => {
    const db = store.open();
    seedSession(db, 's-before', 0);
    seedSession(db, 's-after', 10 * MINUTE);

    expect(db.historySync.counts(T0 + 5 * MINUTE).pending).toBe(3);
  });

  it('records the boundary against the deployment it was frozen for', () => {
    const db = store.open();
    db.historySync.rearmFor('fingerprint-a', T0);

    expect(db.historySync.deployment()).toEqual({
      fingerprint: 'fingerprint-a',
      backlogBefore: T0,
    });
  });

  it('has no boundary before any deployment is recorded', () => {
    const db = store.open();
    expect(db.historySync.deployment()).toEqual({
      fingerprint: undefined,
      backlogBefore: undefined,
    });
  });
});
