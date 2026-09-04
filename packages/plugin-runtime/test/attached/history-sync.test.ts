import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { RemoteRequestError } from '@akasecurity/remote';
import type { IngestEvent, RecordAuditEventRequest } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { HistorySyncResult } from '../../src/attached/history-sync.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';

/**
 * The result of a pass that RAN, or a failure naming why it did not.
 *
 * `runHistorySync` returns a union now, so reading `outcome` needs narrowing —
 * and asserting the narrowing is worth more than the optional chain it replaces.
 * A pass that quietly made no attempt used to read as `undefined` on every
 * field, so `expect(attempted(result).sent).toBe(0)` passed for the wrong reason.
 */
function attempted(result: Awaited<ReturnType<typeof runHistorySync>>): HistorySyncResult {
  if (!result.attempted) {
    throw new Error(`expected a pass to run, but it was skipped: ${result.reason}`);
  }
  return result;
}

const ENDPOINT = 'https://plane.example.test';
const OTHER_ENDPOINT = 'https://other.example.test';
const AT = '2026-08-24T10:00:00.000Z';
const FIXTURE = 'placeholder';
const T0 = Date.parse('2026-08-25T00:00:00.000Z');
// Past every seeded row, so a bare count reads totals rather than the backlog.
const ALL = T0 + 365 * 24 * 60 * 60 * 1000;

let home: string;

const seedRows = (sessions = 1): void => {
  const db = openLocalDatabase(dataDirOf(home));
  try {
    for (let i = 0; i < sessions; i += 1) {
      const id = `s-${String(i)}`;
      db.auditEvents.ensureSessionRoot(id, new Date(T0 - 86_400_000 + i).toISOString());
      db.auditEvents.insertAuditEvent({
        id: `${id}-llm`,
        eventType: 'llm_call',
        rootSessionId: id,
        parentId: id,
        startedAt: new Date(T0 - 86_000_000 + i).toISOString(),
      });
    }
  } finally {
    db.close();
  }
};

/**
 * Capture rows, which the structural seeder deliberately does not write.
 *
 * `startedAt` has to land inside a window with a bound at each end: AFTER the
 * attachment (AT), because the lane deliberately ignores pre-attach captures —
 * those are the structural lane's subject and travel without their text — and
 * before now - 30s, so the grace window does not hold them back for the live
 * path. An hour before T0 satisfies both. Two tests override it to exercise each
 * bound.
 */
const seedCaptures = (
  rows: readonly { id: string; content?: string | undefined; sourceTool?: string; atMs?: number }[],
): void => {
  const db = openLocalDatabase(dataDirOf(home));
  try {
    db.auditEvents.ensureSessionRoot('cap-session', new Date(T0 - 86_400_000).toISOString());
    for (const row of rows) {
      db.auditEvents.insertAuditEvent({
        id: row.id,
        eventType: 'prompt',
        rootSessionId: 'cap-session',
        parentId: 'cap-session',
        startedAt: new Date(row.atMs ?? T0 - 3_600_000).toISOString(),
        // `content` omitted entirely for the unexpressible-row case: the input
        // shape is `z.string().optional()`, so undefined is how a row arrives
        // without text — null would not parse.
        ...('content' in row && row.content === undefined
          ? {}
          : { content: row.content ?? `text of ${row.id}` }),
        contentHash: 'b'.repeat(64),
        // An OBJECT, not a JSON string: AuditEventInput takes an AttributeBag
        // and the mapper stringifies it. Passing a pre-encoded string
        // double-encodes, and every row then rebuilds with no source_tool.
        attributes: { source_tool: row.sourceTool ?? 'claude-code' },
      });
      // What makes a capture OWED, and the drain's whole eligibility test. The
      // attached gateway writes this when a live forward does not confirm
      // delivery; a row without it is one no forward ever attempted — a machine
      // that was detached, or never attached — and the drain must not offer it.
      db.historySync.markCaptureOwed(row.id);
    }
  } finally {
    db.close();
  }
};

function attach(opts: { grantFor?: string; credential?: boolean } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      ...(opts.grantFor === undefined
        ? {}
        : {
            historySyncConsent: {
              acknowledgedAt: AT,
              payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
              endpoint: opts.grantFor,
            },
          }),
    },
    home,
  );
  if (opts.credential !== false) {
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: FIXTURE,
      mintedAt: AT,
    });
  }
}

/** The pass, with time and pacing under the test's control. */
type SendBatch = NonNullable<Parameters<typeof runHistorySync>[0]['sendBatch']>;

/**
 * A default `sendOne` derived from a test's own `sendBatch` mock, for the
 * suites written before the single-event route split off it — routing a
 * length-1 call through the same mock keeps every existing assertion about
 * what `sendBatch` was called with intact. A test asserting the single-event
 * route's OWN contract (a resolved call needs no settled count, unlike this
 * shim) passes `sendOne` itself, which `run` below lets win.
 *
 * Overloaded on the argument's own optionality rather than left as one
 * `| undefined` signature: `exactOptionalPropertyTypes` refuses `sendOne:
 * undefined` as a stand-in for omitting the key, so a call site that always
 * has a `sendBatch` (never `undefined`) needs a return type that says so.
 */
function deriveSendOne(sendBatch: SendBatch): (event: RecordAuditEventRequest) => Promise<void>;
function deriveSendOne(
  sendBatch: SendBatch | undefined,
): ((event: RecordAuditEventRequest) => Promise<void>) | undefined;
function deriveSendOne(sendBatch: SendBatch | undefined) {
  if (sendBatch === undefined) return undefined;
  return async (event: RecordAuditEventRequest) => {
    const { settled } = await sendBatch([event]);
    if (settled < 1) throw new Error('test double: sendBatch settled nothing for one row');
  };
}

const run = (over: Partial<Parameters<typeof runHistorySync>[0]> = {}) => {
  let clock = T0;
  const sendOne = deriveSendOne(over.sendBatch);
  return runHistorySync({
    base: home,
    settingsDir: settingsDirOf(home),
    dataDir: dataDirOf(home),
    now: () => clock,
    sleep: () => {
      clock += 1;
      return Promise.resolve();
    },
    random: () => 0,
    ...(sendOne !== undefined ? { sendOne } : {}),
    ...over,
  });
};

const ledger = <T>(fn: (db: ReturnType<typeof openLocalDatabase>) => T): T => {
  const db = openLocalDatabase(dataDirOf(home));
  try {
    return fn(db);
  } finally {
    db.close();
  }
};

/** A sendBatch that takes everything it is offered — the ordinary case. */
const sendBatchOk = (events: readonly RecordAuditEventRequest[]): Promise<{ settled: number }> =>
  Promise.resolve({ settled: events.length });

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-history-pass-'));
});

afterEach(() => {
  removeTree(home);
});

describe('runHistorySync — passes that are never made', () => {
  // `attempted: false` is NOT an outcome: nothing was attempted, and the caller
  // writes no state for it. Recording one would have status describe a
  // deployment this machine never called.
  //
  // Asserted by REASON rather than by "made no pass". These were seven
  // indistinguishable nulls, so a wrong branch — refusing for the credential
  // when the real problem was the grant — satisfied every one of them. The
  // reason is what `aka sync-history --run` prints, so a wrong one is a wrong
  // instruction to a human rather than merely a wrong value.
  it('makes no pass on an unattached machine', async () => {
    await expect(run()).resolves.toEqual({ attempted: false, reason: 'not-attached' });
  });

  it('makes no pass without a grant', async () => {
    attach();
    seedRows();
    await expect(run()).resolves.toEqual({ attempted: false, reason: 'no-consent' });
  });

  it('makes no pass when the grant names another deployment', async () => {
    attach({ grantFor: OTHER_ENDPOINT });
    seedRows();
    await expect(run()).resolves.toEqual({ attempted: false, reason: 'no-consent' });
  });

  it('makes no pass without a usable credential', async () => {
    attach({ grantFor: ENDPOINT, credential: false });
    seedRows();
    await expect(run()).resolves.toEqual({ attempted: false, reason: 'credential-unusable' });
  });

  // Two drains would send the same rows and the far side would settle it, so
  // this saves request budget rather than correctness — but it should still hold.
  it('makes no pass while another process holds the claim', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    ledger((db) => db.historySync.claim(999_999, 'another-host', T0, 60_000));

    await expect(run()).resolves.toEqual({ attempted: false, reason: 'already-running' });
  });
});

describe('runHistorySync — draining', () => {
  it('sends every pending structural row and marks it delivered', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(2);
    const sent: string[] = [];

    const result = await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(attempted(result).outcome).toBe('ok');
    expect(attempted(result).sent).toBe(4);
    expect(sent).toEqual(['s-0', 's-0-llm', 's-1', 's-1-llm']);
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 0, sent: 4 });
  });

  // The receiving side has real self-referencing foreign keys and stubs no
  // missing root, so a leaf that overtakes its session is rejected outright.
  it('sends a session root before any of its leaves', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    const sent: string[] = [];

    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent.indexOf('s-0')).toBeLessThan(sent.indexOf('s-0-llm'));
  });

  it('leaves the claim free for the next pass', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    await run({ sendBatch: sendBatchOk });

    expect(ledger((db) => db.historySync.lease()?.ownerPid)).toBeNull();
  });

  it('does nothing on a second pass once everything has gone', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    await run({ sendBatch: sendBatchOk });

    const again = await run({
      sendBatch: () => Promise.reject(new Error('should not be called')),
    });
    expect(attempted(again).sent).toBe(0);
  });
});

describe('runHistorySync — failures', () => {
  // Terminal in a way a timeout is not: the credential may have died with an
  // offboarded member, and every later row would fail identically.
  it('stops at the first refusal rather than working through the backlog', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(3);
    let calls = 0;

    const result = await run({
      sendBatch: () => {
        calls += 1;
        return Promise.reject(new RemoteRequestError(401));
      },
    });

    expect(attempted(result).outcome).toBe('refused');
    expect(calls).toBe(1);
    expect(ledger((db) => db.historySync.counts(ALL).sent)).toBe(0);
  });

  // Everything unacknowledged stays pending: an outage must never become data
  // loss, which is the whole reason the stamp comes after the ack.
  it('leaves everything pending when the deployment is unreachable', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(2);

    const result = await run({ sendBatch: () => Promise.reject(new Error('socket hang up')) });

    expect(attempted(result).outcome).toBe('unreachable');
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 4, sent: 0 });
  });

  it('retries a failure that might not repeat before giving up', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    let calls = 0;

    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        calls += 1;
        return calls < 3
          ? Promise.reject(new Error('transient'))
          : Promise.resolve({ settled: events.length });
      },
    });

    // Both rows ride ONE request, so the ladder runs once: two transient
    // failures, then a success that lands the whole batch.
    expect(calls).toBe(3);
    expect(ledger((db) => db.historySync.counts(ALL).sent)).toBe(2);
  });

  // A body the deployment understood and rejected cannot be fixed by sending it
  // again, so it becomes a counted skip rather than an endless retry.
  it('permanently skips a row the deployment refuses on its merits', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    const result = await run({ sendBatch: () => Promise.reject(new RemoteRequestError(400)) });

    expect(attempted(result).skipped).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL).skipped)).toBe(2);
  });

  // A batch ack is an aggregate count, so a rejection names no row. Re-sending
  // the same batch would fail identically for ever, and skipping all of it would
  // discard good rows for one bad one — so the bad one gets found.
  it('isolates the offending row rather than losing the whole batch', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    const result = await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) =>
        events.some((e) => e.id.endsWith('-llm'))
          ? Promise.reject(new RemoteRequestError(400))
          : Promise.resolve({ settled: events.length }),
    });

    expect(attempted(result).sent).toBe(1);
    expect(attempted(result).skipped).toBe(1);
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ sent: 1, skipped: 1 });
  });

  // A PARTIAL ack is not a delivery of the whole batch. `AuditEventBatchAck`'s
  // `accepted` is an aggregate the wire contract does not tie to the chunk's
  // own length, so a deployment this plugin does not ship may answer
  // {accepted: 1} for a batch of 2 — and trusting the call resolving would
  // stamp both delivered and never re-offer the one that was not. Re-reading
  // the same rows next pass and under-accepting again would wedge the lane for
  // ever, so the batch is split until the answer is unambiguous — the
  // structural twin of the capture lane's equivalent test above.
  it('recovers a batch the deployment accepted FEWER of than it was sent', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1); // one session root + one llm_call: a batch of 2
    const batchSizes: number[] = [];
    const singles: string[] = [];

    const result = await run({
      // Claims only one of the two sent as a batch — which one is not
      // knowable from the ack, so recovery has to isolate.
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        batchSizes.push(events.length);
        return Promise.resolve({ settled: 1 });
      },
      // Isolation re-sends each row over the SINGLE-EVENT route rather than a
      // length-1 call through the batch mock above — a resolved call here
      // needs no settled count to trust; see sendChunk's `sendSingleRow`.
      sendOne: (event: RecordAuditEventRequest) => {
        singles.push(event.id);
        return Promise.resolve();
      },
    });

    // The batch attempt happened once; both rows were then recovered singly,
    // each over the unambiguous route rather than a second batch call.
    expect(batchSizes).toEqual([2]);
    expect(singles).toEqual(['s-0', 's-0-llm']);
    expect(attempted(result).outcome).toBe('ok');
    expect(attempted(result).sent).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 0, sent: 2 });
  });

  // The floor under that: a chunk of exactly one row never goes through the
  // batch route's aggregate ack at all, precisely because that ack is
  // unanswerable at size one — see `sendSingleRow`'s own docblock. A resolved
  // single-event call is therefore delivery outright, including the case the
  // module's own docblock names: a crash between an ack and `markSynced`
  // means the next pass re-sends a row the deployment already has, and an
  // idempotent re-delivery must not read as a stall.
  it('marks a lone pending row delivered on a resolved single-event send', async () => {
    attach({ grantFor: ENDPOINT });
    const db = openLocalDatabase(dataDirOf(home));
    try {
      // A session root with no child event is one pending structural row —
      // no isolation needed to reach `sendSingleRow` from the top.
      db.auditEvents.ensureSessionRoot('s-lone', new Date(T0 - 86_400_000).toISOString());
    } finally {
      db.close();
    }

    const result = await run({ sendOne: () => Promise.resolve() });

    expect(attempted(result).outcome).toBe('ok');
    expect(attempted(result).sent).toBe(1);
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 0, sent: 1 });
  });

  // The other side of that route: nothing threw before, and now something
  // genuinely does — a real connectivity failure, not an ambiguous ack — so
  // the row stays owed and the pass reports the deployment unreachable.
  it('leaves a lone pending row owed when the single-event route cannot be reached', async () => {
    attach({ grantFor: ENDPOINT });
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot('s-lone', new Date(T0 - 86_400_000).toISOString());
    } finally {
      db.close();
    }

    const result = await run({ sendOne: () => Promise.reject(new Error('socket hang up')) });

    expect(attempted(result).outcome).toBe('unreachable');
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 1, sent: 0 });
  });

  // Hitting the budget PAUSES the drain rather than failing it: the remainder
  // stays pending and the next pass resumes from the ledger.
  it('checkpoints and pauses when the pass budget runs out', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(3);
    let clock = T0;

    const result = await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      passBudgetMs: 10,
      now: () => clock,
      sleep: () => {
        clock += 100;
        return Promise.resolve();
      },
      random: () => 0,
      sendBatch: sendBatchOk,
    });

    expect(attempted(result).outcome).toBe('interrupted');
    expect(ledger((db) => db.historySync.counts(ALL).pending)).toBeGreaterThan(0);
  });
});

describe('runHistorySync — changing deployment', () => {
  // Delivery is a fact about ONE recipient. Rows sent to the deployment a
  // machine has left are undelivered as far as the next one is concerned.
  it('re-arms rows delivered to a previous deployment', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    await run({ sendBatch: sendBatchOk });
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({ pending: 0, sent: 2 });

    // Re-point the machine, and grant for the new place.
    applyOnboarding(
      {
        controlPlane: { endpoint: OTHER_ENDPOINT, attachedAt: AT },
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: OTHER_ENDPOINT,
        },
      },
      home,
    );
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: OTHER_ENDPOINT,
      apiKey: FIXTURE,
      mintedAt: AT,
    });

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual(['s-0', 's-0-llm']);
  });
});

describe('runHistorySync — the backlog boundary', () => {
  // The bug this exists for: without a cutoff the drain re-sends everything the
  // live forward path already delivered. That is duplicate traffic for the life
  // of the install on a credential this job must not exhaust — and because a
  // re-posted SESSION ROOT is an update rather than a no-op, it overwrites the
  // inventory ids the live path resolved with the nothing this lane sends.
  it('never sends a row recorded after the machine attached', async () => {
    attach({ grantFor: ENDPOINT });
    const db = openLocalDatabase(dataDirOf(home));
    try {
      // Before the attachment: this drain's to send.
      db.auditEvents.ensureSessionRoot('s-old', new Date(Date.parse(AT) - 60_000).toISOString());
      // After it: the live path's, and already delivered with resolved ids.
      db.auditEvents.ensureSessionRoot('s-new', new Date(Date.parse(AT) + 60_000).toISOString());
    } finally {
      db.close();
    }

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual(['s-old']);
  });

  // A key ROTATION re-attaches to the same deployment and re-stamps attachedAt.
  // The boundary must not follow it, or the backlog widens back over everything
  // the live path delivered since the first attach.
  it('does not widen the backlog when the machine re-attaches to the same deployment', async () => {
    attach({ grantFor: ENDPOINT });
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot('s-live', new Date(Date.parse(AT) + 60_000).toISOString());
    } finally {
      db.close();
    }
    await run({ sendBatch: sendBatchOk });

    // Rotate: same endpoint, a later attachedAt.
    applyOnboarding(
      {
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-26T10:00:00.000Z' },
      },
      home,
    );

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual([]);
  });
});

describe('runHistorySync — reading the deployment right', () => {
  // A 401 answered with an oversized body rejects as the TRANSPORT error, which
  // carries a status too. Reading the prototype instead of the field would call
  // that a network outage: four attempts, then "paused — deployment
  // unreachable", sending the user to look at their network instead of
  // re-attaching.
  it('treats a refusal as terminal however the transport reports it', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(2);
    let calls = 0;

    const result = await run({
      sendBatch: () => {
        calls += 1;
        // Shaped like the transport's own body-refused rejection: a status, and
        // not the request-error prototype.
        return Promise.reject(Object.assign(new Error('body too large'), { status: 401 }));
      },
    });

    expect(attempted(result).outcome).toBe('refused');
    expect(calls).toBe(1);
  });

  // The breaker's stamp is never cleared by elapsing, and the half-open probe
  // re-stamps it before every attempt. Treating any stamp as "open" would hold
  // the drain off through the whole window in which the live path has resumed
  // probing — and on a flaky deployment, indefinitely.
  it('runs when the breaker stamp is older than the cooldown', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    writeFileSync(
      join(dataDirOf(home), 'attached-state.json'),
      JSON.stringify({ consecutiveFailures: 3, openedAtMs: T0 - 10 * 60_000, lastFailure: null }),
    );

    const result = await run({ sendBatch: sendBatchOk });

    expect(attempted(result).sent).toBe(2);
  });

  it('skips while the breaker stamp is INSIDE the cooldown, and names that reason', async () => {
    // The other side of the case above. A drain that returns here did nothing,
    // and the remedy is to WAIT rather than to re-attach — which is why
    // `aka sync-history --run` has its own line for it. Without a pass that can
    // actually produce this reason, that line is a string nothing reaches.
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    writeFileSync(
      join(dataDirOf(home), 'attached-state.json'),
      JSON.stringify({
        consecutiveFailures: 3,
        openedAtMs: T0 - 1_000,
        lastFailure: 'unreachable',
      }),
    );

    await expect(run({ sendBatch: sendBatchOk })).resolves.toEqual({
      attempted: false,
      reason: 'breaker-open',
    });
  });

  it('reports `failed` rather than throwing when the store cannot be opened', async () => {
    // The catch is this drain's whole contract: it runs detached with nobody
    // watching, so a throw would be an unhandled rejection whose only effect is
    // a status nobody reads. It reports instead — and the reason has to REACH
    // the caller, or the CLI's "could not complete" line is unreachable too.
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    await expect(
      run({
        openStore: () => {
          throw new Error('database disk image is malformed');
        },
      }),
    ).resolves.toEqual({ attempted: false, reason: 'failed' });
  });
});

describe('runHistorySync — detach and re-attach', () => {
  const rootAt = (id: string, iso: string): void => {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot(id, iso);
    } finally {
      db.close();
    }
  };

  // The window between a detach and a re-attach is forwarded by NOTHING: the
  // live path is off because the machine is not attached, and the drain's
  // boundary was frozen at the first attachment. Without the hand-off at detach
  // those rows are delivered by neither path and reported outstanding by
  // neither — the pending count calls the backlog drained.
  it('picks up what was recorded while detached', async () => {
    attach({ grantFor: ENDPOINT });
    rootAt('s-pre', '2026-08-20T00:00:00.000Z'); // before the first attach
    await run({ sendBatch: sendBatchOk });

    // Detach: hand the attached period over and release the boundary.
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.historySync.closeAttachedWindow(Date.parse(AT), Date.parse(AT) + 1_000);
    } finally {
      db.close();
    }
    rootAt('s-detached', '2026-08-24T12:00:00.000Z'); // recorded while detached

    // Re-attach to the SAME deployment, later.
    applyOnboarding(
      { controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-24T18:00:00.000Z' } },
      home,
    );

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual(['s-detached']);
  });

  // The hand-off must not re-open the attached period itself: those rows were
  // the live path's, and re-sending a session root overwrites the inventory ids
  // it resolved.
  it('does not re-send what the live path owned while attached', async () => {
    attach({ grantFor: ENDPOINT });
    rootAt('s-live', '2026-08-24T12:00:00.000Z'); // after the attach: live path's
    await run({ sendBatch: sendBatchOk });

    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.historySync.closeAttachedWindow(Date.parse(AT), Date.parse(AT) + 1_000);
    } finally {
      db.close();
    }
    applyOnboarding(
      { controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-24T18:00:00.000Z' } },
      home,
    );

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual([]);
  });

  // A different deployment still discards the stamps — what the old one holds
  // is nothing to the new one.
  it('still starts over when the re-attach names a different deployment', async () => {
    attach({ grantFor: ENDPOINT });
    rootAt('s-pre', '2026-08-20T00:00:00.000Z');
    await run({ sendBatch: sendBatchOk });

    applyOnboarding(
      {
        controlPlane: { endpoint: OTHER_ENDPOINT, attachedAt: '2026-08-24T18:00:00.000Z' },
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: OTHER_ENDPOINT,
        },
      },
      home,
    );
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: OTHER_ENDPOINT,
      apiKey: FIXTURE,
      mintedAt: AT,
    });

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toContain('s-pre');
  });
});

describe('runHistorySync — a rotation before the detach', () => {
  const rootAt = (id: string, iso: string): void => {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot(id, iso);
    } finally {
      db.close();
    }
  };

  // `attachedAt` is re-stamped on every attach, a rotation included; the
  // boundary deliberately is not. Handing the window over from `attachedAt`
  // would stamp only from the rotation onwards, leaving the FIRST attached
  // period unstamped — and the next re-attach freezes past it, so the drain
  // re-sends rows the live path owned.
  it('hands over the whole attached period, not just since the last rotation', async () => {
    attach({ grantFor: ENDPOINT });
    await run({ sendBatch: sendBatchOk }); // freezes the boundary at AT

    // Recorded while attached, BEFORE the rotation: the live path's.
    rootAt('s-first-window', '2026-08-24T12:00:00.000Z');

    // Rotate: same endpoint, a later attachedAt. The boundary stays at AT.
    applyOnboarding(
      { controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-24T20:00:00.000Z' } },
      home,
    );
    await run({ sendBatch: sendBatchOk });

    // Detach: hand the attached period over, measured from the boundary.
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.historySync.closeAttachedWindow(
        Date.parse('2026-08-24T20:00:00.000Z'),
        Date.parse('2026-08-24T22:00:00.000Z'),
      );
    } finally {
      db.close();
    }

    // Re-attach later, same endpoint.
    applyOnboarding(
      { controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-25T06:00:00.000Z' } },
      home,
    );

    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).not.toContain('s-first-window');
    expect(sent).toEqual([]);
  });
});

// The capture lane. Everything here is about the property the structural lane
// exists to NOT have: these rows carry the user's text, so the tests are about
// where that text goes and what happens when it is not confirmed delivered.
describe('runHistorySync — the capture lane', () => {
  const lanes = () => {
    const structural: RecordAuditEventRequest[] = [];
    const captures: IngestEvent[] = [];
    return {
      structural,
      captures,
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        structural.push(...events);
        return Promise.resolve({ settled: events.length });
      },
      sendCaptures: (events: readonly IngestEvent[]) => {
        captures.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    };
  };

  it('sends a queued capture WITH its text, and settles it', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-1']);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // THE ROUTING RULE. A capture on the structural lane reaches a route that
  // persists `content` verbatim, and arrives stripped of the text anyway
  // because rebuildAuditEvent has no `content` key. Neither half is acceptable.
  it('never puts a capture on the structural lane', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    seedCaptures([{ id: 'cap-1' }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.structural.some((e) => e.eventType === 'prompt')).toBe(false);
    expect(l.captures).toHaveLength(1);
  });

  // Settlement follows the ACK, never the call returning. A deployment that
  // takes nothing must leave the row owed rather than stamped.
  it('leaves a capture owed when the deployment takes nothing', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    await run({
      sendBatch: sendBatchOk,
      sendCaptures: () => Promise.resolve({ settled: 0 }),
    });

    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL)).map((r) => r.id)).toEqual([
      'cap-1',
    ]);
  });

  it('leaves a capture owed when the send throws', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    await run({
      sendBatch: sendBatchOk,
      sendCaptures: () => Promise.reject(new Error('unreachable')),
    });

    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL)).map((r) => r.id)).toEqual([
      'cap-1',
    ]);
  });

  // The read has no cursor — it re-reads the head of the unstamped set each
  // time — so a row that can never be rebuilt would be the head of every page
  // for ever. It has to be skipped, not retried.
  it('permanently skips an unexpressible capture instead of stalling on it', async () => {
    attach({ grantFor: ENDPOINT });
    // No content: required on the wire, so this row can never be expressed.
    seedCaptures([{ id: 'cap-bad', content: undefined }, { id: 'cap-good' }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-good']);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // The grace window leaves a just-recorded capture to the live path, so the
  // common case stays one send rather than a race the receiver has to dedup.
  it('leaves a capture newer than the grace window to the live path', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-fresh', atMs: T0 - 1000 }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures).toEqual([]);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL)).map((r) => r.id)).toEqual([
      'cap-fresh',
    ]);
  });

  // THE STALL. The capture read has no cursor: it re-reads the head of the
  // unstamped set every time. So a row the deployment rejects on its merits is
  // the head of every future page on every future pass, and treating that
  // rejection as an outage retires the lane for good while status says only
  // 'unreachable'. The structural lane isolates for exactly this reason; this
  // one has to as well, and is MORE exposed — bigger batches, user text in every
  // row, and no outbound validation in ingestEvents.
  it('isolates a permanently-rejected capture rather than stalling the lane', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-bad' }, { id: 'cap-good' }]);

    const delivered: string[] = [];
    const result = await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events: readonly IngestEvent[]) => {
        if (events.some((e) => e.content === 'text of cap-bad')) {
          return Promise.reject(new RemoteRequestError(400));
        }
        delivered.push(...events.map((e) => e.content));
        return Promise.resolve({ settled: events.length });
      },
    });

    // Asserted on the CAPTURE lane, not on `result.sent` — seedCaptures writes a
    // session root, which is a structural row the other lane also delivers, so
    // the pass total counts work this test is not about.
    expect(delivered).toEqual(['text of cap-good']);
    expect(attempted(result).skipped).toBe(1);
    // Neither row is offered again: one settled, one permanently skipped. That
    // is what stops the next pass re-reading this same rejected page.
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // A dead credential is terminal for the pass, not one bad row: every later
  // capture would fail the same way, and skipping them would be data loss.
  it('stops the pass on a refused credential without skipping anything', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }, { id: 'cap-2' }]);

    const result = await run({
      sendBatch: sendBatchOk,
      sendCaptures: () => Promise.reject(new RemoteRequestError(403)),
    });

    expect(attempted(result).skipped).toBe(0);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toHaveLength(2);
  });

  // An attribute the wire constrains more tightly than the column does — a
  // correlation_id that is not a uuid — must be caught HERE, not by a 400 the
  // cursorless read would replay for ever.
  it('drops an unusable optional attribute rather than the capture', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);
    // Rewrite the row's bag to carry a non-uuid correlation id.
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.insertAuditEvent({
        id: 'cap-legacy',
        eventType: 'prompt',
        rootSessionId: 'cap-session',
        parentId: 'cap-session',
        startedAt: new Date(T0 - 3_600_000).toISOString(),
        content: 'legacy text',
        contentHash: 'c'.repeat(64),
        attributes: { source_tool: 'claude-code', correlation_id: 'legacy-7' },
      });
      db.historySync.markCaptureOwed('cap-legacy');
    } finally {
      db.close();
    }

    const sent: IngestEvent[] = [];
    await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events: readonly IngestEvent[]) => {
        sent.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    });

    // BOTH went. The legacy row's payload is what the outbox exists to deliver,
    // so the unusable OPTIONAL field is dropped and the capture travels — rather
    // than the row being skipped, which would write synced_at = -1 and put that
    // prompt permanently out of reach with nothing reporting it.
    expect(sent.map((e) => e.content).sort()).toEqual(['legacy text', 'text of cap-1']);
    expect(sent.find((e) => e.content === 'legacy text')?.metadata?.correlationId).toBeUndefined();
    expect(ledger((db2) => db2.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // STARVATION. The capture lane used to run only after the structural loop had
  // emptied the entire backlog, so on the machines with the largest pre-attach
  // history the half the user was newly asked about waited weeks behind it. A
  // reserved slice of the pass budget is what stops that; this drives a
  // structural backlog too large to finish and requires captures to move anyway.
  it('drains captures even while a large structural backlog remains', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(40);
    seedCaptures([{ id: 'cap-1' }]);

    const l = lanes();
    let clock = T0;
    await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      // Each structural send burns a large slice of the pass, so the backlog
      // cannot finish inside it. Before the reserved share, that meant the
      // capture never went at all.
      now: () => clock,
      sleep: () => {
        clock += 4_000;
        return Promise.resolve();
      },
      random: () => 0,
      sendBatch: l.sendBatch,
      sendOne: deriveSendOne(l.sendBatch),
      sendCaptures: l.sendCaptures,
    });

    // Positive control: the structural lane really did run and really did not
    // finish, so this is not a case where captures won by default.
    expect(l.structural.length).toBeGreaterThan(0);
    expect(ledger((db) => db.historySync.counts(ALL).pending)).toBeGreaterThan(0);
    // ...and the capture went regardless.
    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-1']);
  });

  // THE SLICE HANDS BACK. Reserving a share for captures is only half of the
  // reciprocity; without the other half, a pass whose capture lane found nothing
  // owed — the normal case on a machine whose live forwarding works — returns
  // with a third of its budget unspent while the structural backlog it was
  // reserved from is still there.
  it('returns the unused capture slice to the structural lane', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(40);
    // No captures owed at all, so the reserved share is not needed this pass.
    const l = lanes();
    let clock = T0;
    await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      now: () => clock,
      sleep: () => {
        clock += 4_000;
        return Promise.resolve();
      },
      random: () => 0,
      sendBatch: l.sendBatch,
      sendOne: deriveSendOne(l.sendBatch),
      sendCaptures: l.sendCaptures,
    });

    expect(l.captures).toEqual([]);
    // A floor BETWEEN the two behaviours, not merely above zero. Measured on this
    // fixture: 60 structural rows delivered when the unused slice is handed back,
    // 42 when it is not — so a threshold under 42 passes either way and asserts
    // nothing. The first version of this test used 20 and was exactly that.
    // Elapsed time is not the assertion because the clock here is fake; what the
    // extra budget buys is rows, so rows are what is counted.
    expect(l.structural.length).toBeGreaterThan(50);
  });

  // A PARTIAL ack is not a delivery of the whole batch. IngestAck constrains
  // accepted/duplicates only to be non-negative, so a deployment this plugin
  // does not ship may answer 40 for a batch of 100 — and stamping all 100 would
  // lose 60 rows for ever with the ledger reading "delivered".
  // A deployment that under-accepts is not an outage, and must not be treated as
  // one: the read has no cursor, so abandoning the batch means re-reading the
  // same rows next pass, under-accepting again, and wedging the lane for ever
  // while status blames a deployment that is reachable and answering. The ack
  // names no row, so the batch is split until the answer is unambiguous.
  it('isolates a partly-taken batch instead of wedging the lane', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }, { id: 'cap-2' }]);

    const delivered: string[] = [];
    await run({
      sendBatch: sendBatchOk,
      // Caps at one per request, whatever it is offered.
      sendCaptures: (events: readonly IngestEvent[]) => {
        if (events.length > 1) return Promise.resolve({ settled: 1 });
        delivered.push(...events.map((e) => e.content));
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(delivered.sort()).toEqual(['text of cap-1', 'text of cap-2']);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // The floor under that: a SINGLE row the deployment takes nothing of is not
  // stampable — the ack gave no verdict to skip on — so it stays owed and the
  // pass stops rather than inventing one.
  it('leaves a single row owed when the deployment takes none of it', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    await run({
      sendBatch: sendBatchOk,
      sendCaptures: () => Promise.resolve({ settled: 0 }),
    });

    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL)).map((r) => r.id)).toEqual([
      'cap-1',
    ]);
  });

  // A blip is what a retry ladder is for. Returning on the first 'retry' verdict
  // would end the capture drain for the whole pass inside a budget with room for
  // four attempts, so a deployment that fails once per pass would never let the
  // capture backlog shrink while the structural lane drained normally.
  it('retries a transient failure rather than ending the pass', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    let attempts = 0;
    await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events: readonly IngestEvent[]) => {
        attempts += 1;
        return attempts === 1
          ? Promise.reject(new RemoteRequestError(503))
          : Promise.resolve({ settled: events.length });
      },
    });

    expect(attempts).toBe(2);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // `counts` is structural-only, so on its own it reports the drain finished the
  // moment the pre-attach backlog empties — which would pin completedAtMs for
  // the life of the install while the capture lane still owed rows.
  it('reports captures still owed when the structural backlog is empty', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    const result = await run({
      sendBatch: sendBatchOk,
      // The deployment takes nothing, so the capture stays owed.
      sendCaptures: () => Promise.resolve({ settled: 0 }),
    });

    expect(attempted(result).capturesPending).toBe(true);
  });

  it('reports nothing owed once the capture lane drains', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);

    const result = await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events: readonly IngestEvent[]) => Promise.resolve({ settled: events.length }),
    });

    expect(attempted(result).capturesPending).toBe(false);
  });

  // WHAT MAKES A CAPTURE ELIGIBLE, and it is a privacy assertion rather than a
  // scoping one. The disclosure says the pre-attach half sends "the record of
  // activity" and that only what a live send could not deliver carries its TEXT.
  // A row nothing marked is a row no live send ever attempted — recorded before
  // this machine attached, or while it was detached — and shipping it would put
  // that text on the wire under copy promising the opposite. The marker is what
  // makes that structural: a detached machine never reaches the attached
  // gateway, so nothing can mark its captures.
  it('never drains a capture no live forward ever attempted', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-owed' }]);
    // Recorded exactly as the others, but never marked — the shape a detached
    // or pre-attach machine leaves behind.
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.insertAuditEvent({
        id: 'cap-unattempted',
        eventType: 'prompt',
        rootSessionId: 'cap-session',
        parentId: 'cap-session',
        startedAt: new Date(T0 - 3_600_000).toISOString(),
        content: 'text of cap-unattempted',
        contentHash: 'b'.repeat(64),
        attributes: { source_tool: 'claude-code' },
      });
    } finally {
      db.close();
    }
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-owed']);
  });

  // The consent gate is the whole reason payload v2 exists: without a valid
  // grant no pass is made at all, so no capture text leaves the machine.
  it('sends no capture without a valid grant', async () => {
    attach();
    seedCaptures([{ id: 'cap-1' }]);
    const l = lanes();

    await expect(run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures })).resolves.toEqual({
      attempted: false,
      reason: 'no-consent',
    });

    expect(l.captures).toEqual([]);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toHaveLength(1);
  });
});
