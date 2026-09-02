import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { SqliteHistorySyncRepository } from '../../src/repositories/history-sync.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import { explain, recordingConnection } from '../helpers/query-plans.ts';
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

  // The capture half does NOT re-arm, and that is the rule rather than an
  // omission. A capture recorded under deployment A is pre-attach relative to B,
  // and the grant says the pre-attach half sends the record of activity, not its
  // text — so B is entitled to the structural rows (which do re-arm, above) and
  // not to the prompts. Re-arming captures would also be inert: the capture lane
  // reads `started_at >= :since`, so every row a deployment change clears sits
  // on the wrong side of the new boundary and is never offered again. The only
  // effect would be to un-stamp delivered rows for ever.
  it('leaves delivered CAPTURES stamped when the deployment changes', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markSynced(['s-1-prompt'], T0);

    db.historySync.rearmFor('fingerprint-b', ALL);

    // Still delivered: the new deployment is not owed this text.
    expect(db.historySync.pendingCaptureRows(10, 0, ALL)).toEqual([]);
    // ...while the structural rows it IS owed came back.
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
      // Set from the same instant on a deployment change, and left alone after.
      captureFloor: T0,
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

describe('SqliteHistorySyncRepository — closing the attached period', () => {
  // The boundary is where the live path's period BEGINS, and it survives a key
  // rotation while the attachment's own timestamp does not. Measuring the
  // hand-off from the timestamp would leave everything before the last rotation
  // unstamped, and the next re-attach would freeze past it — so the drain would
  // re-send rows the live path owned.
  it('stamps from the boundary, not from the mark it is given', () => {
    const db = store.open();
    seedSession(db, 's-before', 0); // before the boundary: the drain's
    seedSession(db, 's-attached', 20 * MINUTE); // after it: the live path's
    db.historySync.rearmFor('fp', T0 + 10 * MINUTE);

    // A mark LATER than the boundary, as a post-rotation attachedAt would be.
    db.historySync.closeAttachedWindow(T0 + 30 * MINUTE, T0 + 40 * MINUTE);

    // The attached period is handed over whole, despite the later mark.
    expect(db.historySync.pendingSessions(10, ALL)).toEqual(['s-before']);
  });

  it('releases the boundary so the next attachment can freeze its own', () => {
    const db = store.open();
    db.historySync.rearmFor('fp', T0);
    db.historySync.closeAttachedWindow(T0, T0 + MINUTE);

    expect(db.historySync.deployment()).toEqual({
      fingerprint: 'fp',
      backlogBefore: undefined,
      // A detach releases the STRUCTURAL boundary only. The capture floor is the
      // first attachment to this deployment and survives, or a re-attach would
      // step it over everything the last attached period left owed.
      captureFloor: T0,
    });
  });

  // Freezing again keeps what was delivered to this same deployment; only a
  // change of deployment discards it.
  it('freezes a new boundary without discarding the stamps', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.rearmFor('fp', ALL);
    db.historySync.markSynced(['s-1'], T0);

    db.historySync.freezeBoundary(ALL);

    expect(db.historySync.counts(ALL).sent).toBe(1);
    expect(db.historySync.deployment().backlogBefore).toBe(ALL);
  });

  // With nothing ever frozen, the mark it is given is the only one on file.
  it('falls back to the given mark when no boundary was ever frozen', () => {
    const db = store.open();
    seedSession(db, 's-before', 0);
    seedSession(db, 's-after', 20 * MINUTE);

    db.historySync.closeAttachedWindow(T0 + 10 * MINUTE, T0 + 40 * MINUTE);

    expect(db.historySync.pendingSessions(10, ALL)).toEqual(['s-before']);
  });
});

// The delivery-state partition backs a surface that reports what has been sent,
// what is going out now, and what is still waiting. It is a different read from
// `counts()` — that one serves the drain and deliberately does not partition.
describe('SqliteHistorySyncRepository — the delivery-state partition', () => {
  it('puts every tracked row in exactly one state', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    // Three structural rows per session; the capture leaf is not tracked yet.
    const p = db.historySync.partition();
    expect(p.total).toBe(3);
    expect(p.queued + p.inProgress + p.synced + p.failed).toBe(p.total);
    expect(p).toMatchObject({ queued: 3, inProgress: 0, synced: 0, failed: 0 });
  });

  it('moves a row through claimed, then settled', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.claimRows(['s-1'], T0 + MINUTE);
    expect(db.historySync.partition()).toMatchObject({ queued: 2, inProgress: 1, synced: 0 });

    db.historySync.markSynced(['s-1'], T0 + 2 * MINUTE);
    // Settling clears the claim in the same write, so the row cannot read as
    // both delivered and in flight.
    expect(db.historySync.partition()).toMatchObject({ queued: 2, inProgress: 0, synced: 1 });
  });

  it('returns a claim to the queue when a send fails', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.claimRows(['s-1', 's-1-llm'], T0);
    expect(db.historySync.partition().inProgress).toBe(2);

    db.historySync.releaseRows(['s-1', 's-1-llm']);
    expect(db.historySync.partition()).toMatchObject({ queued: 3, inProgress: 0 });
  });

  it('never claims a row that already settled', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1'], T0 + MINUTE);
    // A claim racing a settle must not drag a delivered row back into flight.
    db.historySync.claimRows(['s-1'], T0 + 2 * MINUTE);
    expect(db.historySync.partition()).toMatchObject({ synced: 1, inProgress: 0, queued: 2 });
  });

  // The SETTLED half of the scope claim. Its sibling below ('does not yet count
  // captures') pins the static shape — a capture is absent from `total`. This
  // one pins what happens when the live path STAMPS that capture through
  // `markCaptureDelivered`: still nothing, because the row was never counted.
  // Both are needed. Without this one, the docstring's load-bearing sentence —
  // that a live stamp settles nothing visible here — has no test at all, and the
  // stamp could start moving `synced` with the suite fully green.
  it('does not count a capture, before or after the live path stamps it', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    const before = db.historySync.partition();
    expect(before).toMatchObject({ total: 3, queued: 3 });

    db.historySync.markSynced(['s-1-prompt'], T0 + MINUTE);

    // Same numbers: the capture row was never in `total`, so settling it is not
    // a state change this query can see. `synced` staying 0 is the assertion
    // that matters — it is what would break if the capture joined the lane.
    expect(db.historySync.partition()).toMatchObject({ total: 3, queued: 3, synced: 0 });
  });

  it('counts a permanent skip as failed, not as queued', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSkipped(['s-1-llm']);
    const p = db.historySync.partition();
    expect(p).toMatchObject({ queued: 2, failed: 1 });
    expect(p.queued + p.inProgress + p.synced + p.failed).toBe(p.total);
  });

  it('sweeps a claim a dead drain left behind', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.claimRows(['s-1'], T0);
    // Nothing settles it — the process holding it is gone.
    expect(db.historySync.partition().inProgress).toBe(1);

    expect(db.historySync.releaseStaleClaims(T0 + MINUTE)).toBe(1);
    expect(db.historySync.partition()).toMatchObject({ queued: 3, inProgress: 0 });
    // A fresh claim is left alone.
    db.historySync.claimRows(['s-1'], T0 + 10 * MINUTE);
    expect(db.historySync.releaseStaleClaims(T0 + MINUTE)).toBe(0);
    expect(db.historySync.partition().inProgress).toBe(1);
  });

  it('reports zeros on an empty store rather than nulls', () => {
    const db = store.open();
    // SUM() over no rows is NULL; a rendered breakdown must not receive one.
    expect(db.historySync.partition()).toEqual({
      queued: 0,
      inProgress: 0,
      synced: 0,
      failed: 0,
      total: 0,
    });
  });

  it('does not yet count captures — the lane has not been widened', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    // seedSession writes a prompt row too. Until the drain can carry content
    // safely, it is not part of the tracked set and must not appear here.
    expect(db.historySync.partition().total).toBe(3);
  });
});

// The capture lane's read. Everything here is about what the STRUCTURAL reader
// deliberately does not do: no session grouping (the /v1/events route stubs a
// missing root), no backlog boundary (an undelivered capture is owed whenever it
// was recorded), and `content` retained (it is the reason the lane exists).
describe('SqliteHistorySyncRepository — captures the outbox still owes', () => {
  // code_change is a capture kind and is deliberately NOT drained. Its only
  // writers are the scanners, its content is a COMPLETE source file (gitignored
  // scratch included), and it has never been offered to the live path — so
  // draining it would be first-time egress of whole proprietary files under copy
  // that names prompts, replies and tool results. Pinned here because adding it
  // back is one word, and nothing else in the tree would notice.
  it('never offers a code_change, whatever else is owed', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-scan',
      eventType: 'code_change',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'the entire contents of a source file',
      contentHash: 'd'.repeat(64),
    });
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt2',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(2 * MINUTE),
      content: 'a prompt',
    });

    expect(db.historySync.pendingCaptureRows(10, 0, ALL).map((r) => r.id)).toEqual(['s-1-prompt2']);
  });

  it('offers unstamped captures oldest first, and no structural rows', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    seedSession(db, 's-2', 10 * MINUTE);
    const rows = db.historySync.pendingCaptureRows(10, 0, ALL);
    expect(rows.map((r) => r.id)).toEqual(['s-1-prompt', 's-2-prompt']);
    // The structural rows belong to the other lane and must not appear here.
    expect(rows.every((r) => r.eventType === 'prompt')).toBe(true);
  });

  // The whole point of the lane: the text rides along. rebuildAuditEvent drops
  // `content` for the structural route; this reader must not.
  it('carries the captured text', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    expect(db.historySync.pendingCaptureRows(10, 0, ALL)[0]?.content).toBe('the text of a prompt');
  });

  it('does not offer a capture the live path already stamped', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1-prompt'], T0);
    expect(db.historySync.pendingCaptureRows(10, 0, ALL)).toEqual([]);
  });

  it('does not offer a capture another pass has claimed', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.claimRows(['s-1-prompt'], T0);
    expect(db.historySync.pendingCaptureRows(10, 0, ALL)).toEqual([]);
  });

  // The grace window is what keeps this pass off rows the live forward is
  // probably still sending. It is a quietness measure, not a correctness one —
  // but it has to actually bound the read.
  it('holds back a capture newer than the grace window', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    // seedSession writes its prompt at T0 + 3 minutes.
    expect(db.historySync.pendingCaptureRows(10, 0, T0 + 2 * MINUTE)).toEqual([]);
    expect(db.historySync.pendingCaptureRows(10, 0, T0 + 4 * MINUTE).map((r) => r.id)).toEqual([
      's-1-prompt',
    ]);
  });

  it('pages', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    seedSession(db, 's-2', 10 * MINUTE);
    expect(db.historySync.pendingCaptureRows(1, 0, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });
});

// The ledger's reads used to scan `audit_events` — the table captures land in.
// The comments on idx_audit_events_sync and idx_audit_claimed claim the indexes
// serve them; these pin that claim, because a comment cannot notice when a
// column order stops working.
//
// THE SQL IS TAKEN FROM THE REPOSITORY AS IT EXECUTES, never restated here.
// `recordingConnection` captures the statement and the parameters each call
// really ran with (see test/helpers/query-plans.ts); a query spelled a second
// time in this file would be free to drift from the one the ledger runs, and a
// plan assertion over drifted SQL is the most convincing kind of green there
// is — a real plan for a real query that nothing issues.
describe('SqliteHistorySyncRepository — the ledger reads use the index', () => {
  /** The plans for every statement `drive` executes, as one string. */
  const planFor = (drive: (ledger: SqliteHistorySyncRepository) => void): string => {
    // Migrations run on `open()`; `openRaw` only attaches to the file.
    store.open();
    const raw = store.openRaw();
    const recorded: RecordedQuery[] = [];
    drive(new SqliteHistorySyncRepository(recordingConnection(raw, recorded)));
    // Without this a read that stopped issuing SQL would satisfy every
    // assertion below vacuously, and look exactly like one that was optimised.
    expect(recorded.length, 'the driven read issued no statement').toBeGreaterThan(0);
    // EXPLAIN goes through the RAW handle, so the recorder does not capture its
    // own explains and recurse.
    return recorded.flatMap((q) => explain(raw, q).map((row) => row.detail)).join(' | ');
  };

  it('answers the delivery-state partition from the index alone', () => {
    const plan = planFor((ledger) => ledger.partition());
    // COVERING is the property that matters: this read runs on every render of a
    // surface that shows it, and without the index it is a full table scan.
    expect(plan).toContain('idx_audit_events_sync');
    expect(plan).toContain('COVERING INDEX');
    expect(plan).not.toContain('SCAN audit_events');
  });

  it('finds pending sessions on the index that bounds started_at, not the new one', () => {
    const plan = planFor((ledger) => ledger.pendingSessions(10, ALL));
    // The drain's read prefers idx_audit_type_t, which puts started_at directly
    // after event_type; idx_audit_events_sync has the two sync columns in
    // between, so it cannot seek the range as tightly. Asserted rather than
    // assumed: the point is that this read is served by SOME index, and which
    // one is a planner decision worth noticing if it changes.
    expect(plan).toContain('idx_audit_type_t');
    expect(plan).not.toContain('SCAN audit_events');
  });

  // The one WRITE in this block, and the reason it needs its own index.
  it('sweeps stale claims on the partial index, not by scanning the table', () => {
    const plan = planFor((ledger) => {
      ledger.releaseStaleClaims(T0 + MINUTE);
    });
    // idx_audit_events_sync cannot serve this: it leads with event_type, which
    // this predicate does not mention, so the planner has nothing to seek on and
    // falls back to a full pass over the table captures land in — taken while
    // holding the write lock. idx_audit_claimed is the one it can seek.
    expect(plan).toContain('idx_audit_claimed');
    expect(plan).toContain('SEARCH');
    expect(plan).not.toContain('SCAN audit_events');
  });
});
