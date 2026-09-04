import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { seedCaptureBacklogOwed } from '../../src/history-backfill.ts';
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
  // What the attached forward path writes when a live send does not confirm
  // delivery. Without it the row is one nothing ever attempted, which the drain
  // deliberately does not offer.
  db.historySync.markCaptureOwed(`${sessionId}-prompt`);
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

    // The capture row is in none of the structural three — and `capturesSkipped`
    // is its own lifetime figure, zero here because nothing skipped a capture.
    expect(db.historySync.counts(ALL)).toEqual({
      pending: 1,
      sent: 1,
      skipped: 1,
      capturesSkipped: 0,
    });
  });

  // A capture skipped permanently is counted for the LIFE of the store, not for
  // one pass. The surface renders it beside `sent` and `pending`, both lifetime
  // figures, so a per-pass tally there would announce a terminal loss once and
  // then drop it while the rows stayed gone.
  it('counts a permanently skipped capture, and keeps counting it', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSkipped(['s-1-prompt']);

    expect(db.historySync.counts(ALL).capturesSkipped).toBe(1);
    // Still there on a later read, with nothing else having happened.
    expect(db.historySync.counts(ALL).capturesSkipped).toBe(1);
    // ...and it did not leak into the structural tally.
    expect(db.historySync.counts(ALL).skipped).toBe(0);
  });

  it('counts an empty store as nothing rather than throwing', () => {
    const db = store.open();
    expect(db.historySync.counts(ALL)).toEqual({
      pending: 0,
      sent: 0,
      skipped: 0,
      capturesSkipped: 0,
    });
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
  // omission. A DELIVERED capture was sent to A under A's own grant, and B has
  // no claim on what A already received — re-arming it would resend A's text to
  // a deployment A's grant never named. Re-arming would also be inert regardless:
  // the capture lane reads `started_at >= :since`, so every row a deployment
  // change clears sits on the wrong side of the new boundary and is never
  // offered again. The only effect would be to un-stamp delivered rows for ever.
  it('leaves delivered CAPTURES stamped when the deployment changes', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markSynced(['s-1-prompt'], T0);

    db.historySync.rearmFor('fingerprint-b', ALL);

    // Still delivered: the new deployment is not owed this text.
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
    // ...while the structural rows it IS owed came back.
    expect(db.historySync.counts(ALL)).toMatchObject({ pending: 3, sent: 0 });
  });

  // THE DEPLOYMENT-CHANGE LEAK. `outbox_owed` says "a live forward owed this
  // row" — and the forward that owed it belonged to the OLD deployment. Left
  // set, the drain reads it as owed to the new one and ships the old
  // deployment's prompts, with their text, somewhere they were never sent. That
  // is the same leak the removed floor was reset to prevent, so a set-only
  // marker would have been worse than the bound it replaced.
  it('disowns capture markers when the deployment changes', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    // Attach to A FIRST, then let a forward under A mark the row — the real
    // order, and the one that matters: a marker written before any attachment
    // belongs to nobody and is cleared by the same statement.
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markCaptureOwed('s-1-prompt');
    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);

    db.historySync.rearmFor('fingerprint-b', ALL);

    // Owed to nobody now: only a live forward under the NEW deployment can mark
    // it again, and that forward has not run.
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
    // ...while the structural rows the new deployment IS entitled to came back.
    expect(db.historySync.counts(ALL)).toMatchObject({ pending: 3 });
  });

  // THE OTHER HALF OF THE SAME LEAK, in the opposite direction: a caller that
  // has ALREADY confirmed a valid grant for the deployment being armed passes
  // its own bound as the third argument, and the disown above must not eat it.
  // Without this, a machine that grants existing-history consent while
  // attaching to B has that grant's own markers wiped the moment the drain
  // notices the fingerprint changed — before it ever reads them — because the
  // disown cannot tell "a marker A's forward left" from "a marker B's OWN
  // grant just set" apart by looking at the column alone.
  //
  // Built by hand rather than through seedSession, which marks its own
  // capture owed to simulate A's live forward — a different fact from the one
  // this test is isolating, and one the sibling test above already covers.
  it('keeps a fresh backfill for the NEW deployment through the same disown', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'text of a pre-attach prompt',
    });
    // Attached to A first — the real order, and the one that matters: nothing
    // has marked this row owed to anybody yet.
    db.historySync.rearmFor('fingerprint-a', ALL);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);

    // The CLI's own seedCaptureBacklogOwed, at the instant a human grants
    // existing-history consent for B — before the drain has run even once
    // under B, exactly as `aka attach` orders it.
    db.historySync.markCaptureBacklogOwed(T0 + 10 * MINUTE);
    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);

    // The drain's first pass under B. Consent was already confirmed valid for
    // B before this call is reachable — see runHistorySync — so the caller
    // passes the SAME bound as the third argument.
    db.historySync.rearmFor('fingerprint-b', ALL, T0 + 10 * MINUTE);

    // B's own grant survives the switch that just disowned A's leftovers (of
    // which there were none here — the point is that the disown running at
    // all does not also take B's marker with it).
    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });

  // The bound is still a bound: a capture recorded AFTER the grant it is
  // reapplying is the live forward path's to mark, not this repair's — passing
  // the third argument must not silently widen into that territory.
  it('does not reapply the backfill to a capture recorded after its own bound', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(5 * MINUTE),
      content: 'text of a prompt recorded after the grant',
    });
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markCaptureBacklogOwed(T0 + 2 * MINUTE);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);

    db.historySync.rearmFor('fingerprint-b', ALL, T0 + 2 * MINUTE);

    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });

  // The other side of that rule, and the one I only found by breaking it: this
  // method ALSO runs the first time a machine attaches at all (no fingerprint →
  // A), and the markers on disk then were written by A's own live path earlier
  // in the same session. Disowning those empties the outbox at the moment it
  // starts filling — every capture the live path already failed to deliver,
  // dropped, silently.
  it('keeps capture markers on a first attach, which is not a change', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);

    // No previous deployment: the markers belong to this one.
    db.historySync.rearmFor('fingerprint-a', ALL);

    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });

  // Re-attaching to the SAME deployment is not a change either — the recipient
  // is unchanged, so what it is owed is unchanged.
  it('keeps capture markers when the same deployment is re-recorded', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.rearmFor('fingerprint-a', ALL);
    db.historySync.markCaptureOwed('s-1-prompt');

    db.historySync.rearmFor('fingerprint-a', ALL);

    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
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
    // Marked owed exactly like a prompt would be, so the exclusion under test is
    // the KIND filter and not a missing marker.
    db.historySync.markCaptureOwed('s-1-scan');
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt2',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(2 * MINUTE),
      content: 'a prompt',
    });
    db.historySync.markCaptureOwed('s-1-prompt2');

    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt2']);
  });

  // THE MARKER IS THE PREDICATE. It replaced a time window that could not state
  // this in either direction: rows a past attachment left owed fell below a
  // boundary a re-attach moved, and the entire DETACHED span sat above it — so a
  // machine that ran three weeks unattached would have shipped every prompt in
  // them, with text, on re-attaching. A capture nothing marked is one no live
  // forward ever attempted, and it must never be offered.
  it('offers only what a live forward marked owed', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    for (const id of ['unattempted', 'owed']) {
      db.auditEvents.insertAuditEvent({
        id: `s-1-${id}`,
        eventType: 'prompt',
        rootSessionId: 's-1',
        parentId: 's-1',
        startedAt: at(MINUTE),
        content: `text of ${id}`,
      });
    }
    db.historySync.markCaptureOwed('s-1-owed');

    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-owed']);
  });

  it('offers unstamped captures oldest first, and no structural rows', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    seedSession(db, 's-2', 10 * MINUTE);
    const rows = db.historySync.pendingCaptureRows(10, ALL);
    expect(rows.map((r) => r.id)).toEqual(['s-1-prompt', 's-2-prompt']);
    // The structural rows belong to the other lane and must not appear here.
    expect(rows.every((r) => r.eventType === 'prompt')).toBe(true);
  });

  // The whole point of the lane: the text rides along. rebuildAuditEvent drops
  // `content` for the structural route; this reader must not.
  it('carries the captured text', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    expect(db.historySync.pendingCaptureRows(10, ALL)[0]?.content).toBe('the text of a prompt');
  });

  it('does not offer a capture the live path already stamped', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.markSynced(['s-1-prompt'], T0);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });

  it('does not offer a capture another pass has claimed', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    db.historySync.claimRows(['s-1-prompt'], T0);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });

  // The grace window is what keeps this pass off rows the live forward is
  // probably still sending. It is a quietness measure, not a correctness one —
  // but it has to actually bound the read.
  it('holds back a capture newer than the grace window', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    // seedSession writes its prompt at T0 + 3 minutes.
    expect(db.historySync.pendingCaptureRows(10, T0 + 2 * MINUTE)).toEqual([]);
    expect(db.historySync.pendingCaptureRows(10, T0 + 4 * MINUTE).map((r) => r.id)).toEqual([
      's-1-prompt',
    ]);
  });

  it('pages', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);
    seedSession(db, 's-2', 10 * MINUTE);
    expect(db.historySync.pendingCaptureRows(1, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });
});

// The consent-time backfill: the one OTHER writer of `outbox_owed`, and the
// one that reaches a capture the live forward path never touched — a machine
// that ran the whole thing detached has none of its captures marked by
// anything else. Deliberately a separate describe block from the section
// above: those tests are the drain's read, given a marker; these are about
// what writes the marker in the first place.
describe('SqliteHistorySyncRepository — the consent-time backfill', () => {
  it('marks an unattempted capture owed, as of the bound', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'text of a pre-attach prompt',
    });
    // No markCaptureOwed call — this row is exactly what the live forward path
    // never reaches, because it was never attempted.
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);

    db.historySync.markCaptureBacklogOwed(T0 + 2 * MINUTE);
    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });

  // `before` is the caller's OWN "now" at the moment consent was granted, never
  // a boundary this call re-derives — so a capture recorded at or after it must
  // not be swept in, even though it is unattempted in exactly the same way.
  it('does not reach a capture recorded at or after the bound', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(5 * MINUTE),
      content: 'text of a prompt recorded after the grant',
    });

    db.historySync.markCaptureBacklogOwed(T0 + 2 * MINUTE);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });

  // code_change is a capture kind and is deliberately excluded from every
  // capture-lane read — see the sibling test above. The backfill shares
  // CAPTURE_TYPE_LIST with the drain's own read, so this pins that the NEW
  // writer respects the same exclusion rather than assuming it from the
  // reader alone.
  it('never marks a code_change, whatever else is on disk', () => {
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

    db.historySync.markCaptureBacklogOwed(ALL);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });

  // Structural rows are the other lane entirely and must never be pulled into
  // this one — they already have their own re-arm on the structural drain.
  it('never marks a structural row', () => {
    const db = store.open();
    seedSession(db, 's-1', 0);

    db.historySync.markCaptureBacklogOwed(ALL);
    const owedIds = db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id);
    expect(owedIds).toEqual(['s-1-prompt']);
    expect(owedIds).not.toContain('s-1-llm');
    expect(owedIds).not.toContain('s-1-tool');
  });

  it('is idempotent: a repeat call over the same window changes nothing further', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'text of a prompt',
    });

    db.historySync.markCaptureBacklogOwed(ALL);
    db.historySync.markCaptureBacklogOwed(ALL);
    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });

  // A row the drain already settled must stay settled: `synced_at IS NULL` is
  // part of the same WHERE clause the drain's own read uses, not an extra
  // guard bolted on.
  it('does not re-open a capture that already synced', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'text of a prompt',
    });
    db.historySync.markSynced(['s-1-prompt'], T0);

    db.historySync.markCaptureBacklogOwed(ALL);
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);
  });
});

// `seedCaptureBacklogOwed` is the module-level wrapper the three consent-time
// grant sites call — a separate open/mark/close on the SAME file, never a
// method on an already-open handle. These pin its two properties: it really
// does open the store and reach the repository method above, and a store it
// cannot open does not turn a successful consent into a reported failure.
describe('seedCaptureBacklogOwed — the shared consent-time backfill helper', () => {
  it('opens the store, marks the backlog owed, and closes the handle', () => {
    const db = store.open();
    db.auditEvents.ensureSessionRoot('s-1', at(0));
    db.auditEvents.insertAuditEvent({
      id: 's-1-prompt',
      eventType: 'prompt',
      rootSessionId: 's-1',
      parentId: 's-1',
      startedAt: at(MINUTE),
      content: 'text of a prompt',
    });
    expect(db.historySync.pendingCaptureRows(10, ALL)).toEqual([]);

    seedCaptureBacklogOwed(store.dataDir, T0 + 2 * MINUTE);

    expect(db.historySync.pendingCaptureRows(10, ALL).map((r) => r.id)).toEqual(['s-1-prompt']);
  });

  it('is silent, not thrown, when the store cannot be opened', () => {
    // A plain file where a directory belongs: ensureDataDirSync's mkdir fails
    // with ENOTDIR on every platform, which is the fault this helper exists to
    // absorb — the grant it is called after has already been recorded.
    const blocker = join(store.home, 'blocker-file');
    writeFileSync(blocker, '');

    expect(() => {
      seedCaptureBacklogOwed(join(blocker, 'data'), Date.now());
    }).not.toThrow();
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

  // The CAPTURE drain's read, which has no lower bound on started_at and so has
  // nothing to stop a walk without an index of its own. Its "is anything owed?"
  // form runs three times a pass over a table with no retention policy.
  it('finds owed captures on the partial index rather than scanning', () => {
    const plan = planFor((ledger) => ledger.pendingCaptureRows(1, ALL));
    expect(plan).toContain('idx_audit_outbox_owed');
    expect(plan).not.toContain('SCAN audit_events');
    // A temp B-tree for the ORDER BY REMAINS, and is not what this index is for:
    // `event_type IN (…)` is several seeks, so the order cannot come straight
    // off any index of this shape — the pre-existing one sorts too. What the
    // partial index changes is WHAT is sorted. Its entries are owed rows only,
    // so both the seek and the sort are bounded by the outbox rather than by
    // every unsettled capture in a table with no retention policy.
  });

  // The consent-time backfill's own WHERE clause — unbounded below, like the
  // read above, and run at every fresh or repeated grant rather than once.
  // What it MARKS is a separate concern from what it SEEKS: this pins only
  // that finding the rows to mark is an index SEARCH, never a table scan —
  // idx_audit_outbox_owed itself is what the marked set then grows, which is
  // a write-cost property the migration comment on that index states, not
  // one an EXPLAIN QUERY PLAN of this statement can show.
  it('finds the capture backlog to mark on the index, not by scanning', () => {
    const plan = planFor((ledger) => {
      ledger.markCaptureBacklogOwed(ALL);
    });
    expect(plan).toContain('idx_audit_type_t');
    expect(plan).toContain('SEARCH');
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
