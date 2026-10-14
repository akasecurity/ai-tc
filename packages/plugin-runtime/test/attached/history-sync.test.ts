import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  captureWireId,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  openLocalDatabase,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { RemoteRequestError, RemoteRequestInvalid } from '@akasecurity/remote';
import type {
  AttachedCredentialV2,
  IngestEvent,
  ManagedSettingsValues,
  RecordAuditEventRequest,
} from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION, MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../persistence/src/managed-settings.ts';
import type { HistorySyncResult } from '../../src/attached/history-sync.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
import { migratedStore } from '../helpers/store-templates.ts';

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

// THE CREDENTIAL READER, WRAPPED, for the scoped cases at the end of this file.
// They arm `credentialRead` with a usable scoped read rather than writing a
// scoped credential file, so they exercise the drain's scope handling
// independently of what the reader accepts. Unarmed, every call reaches the
// real reader, so every other case here is unaffected.
const credentialRead = vi.hoisted<{ value: unknown }>(() => ({ value: undefined }));
// How many times the pass read settings through the package entry, for the case
// that pins a machine attachment to its single read at pass start.
const settingsReads = vi.hoisted<{ count: number }>(() => ({ count: 0 }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readWorkspaceSettings: (
      ...args: Parameters<typeof actual.readWorkspaceSettings>
    ): ReturnType<typeof actual.readWorkspaceSettings> => {
      settingsReads.count += 1;
      return actual.readWorkspaceSettings(...args);
    },
    readControlPlaneCredentialFile: (
      ...args: Parameters<typeof actual.readControlPlaneCredentialFile>
    ): ReturnType<typeof actual.readControlPlaneCredentialFile> =>
      (credentialRead.value as
        ReturnType<typeof actual.readControlPlaneCredentialFile> | undefined) ??
      actual.readControlPlaneCredentialFile(...args),
  };
});

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
  rows: readonly {
    id: string;
    content?: string | undefined;
    sourceTool?: string;
    atMs?: number;
    // The scope key the capture was stamped with; omitted, it carries none.
    scopeKey?: string;
    // The producer's display slug, stored as the `repo` attribute; omitted,
    // the row carries none.
    repo?: string;
    // `false` leaves the row unmarked: a capture no forward ever attempted.
    owed?: false;
  }[],
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
        attributes: {
          source_tool: row.sourceTool ?? 'claude-code',
          ...(row.scopeKey === undefined ? {} : { scope_key: row.scopeKey }),
          ...(row.repo === undefined ? {} : { repo: row.repo }),
        },
      });
      // What makes a capture OWED, and the drain's whole eligibility test. The
      // attached gateway writes this when a live forward does not confirm
      // delivery; a row without it is one no forward ever attempted — a machine
      // that was detached, or never attached — and the drain must not offer it.
      if (row.owed !== false) db.historySync.markCaptureOwed(row.id);
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
  // The pass opens the store and so do the seeders, and none of these cases is
  // about a store being created: copying the migrated template spares every
  // test a full migration, which is most of what this file cost on Windows.
  migratedStore.seed(dataDirOf(home));
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
  // A 400/413/422 is THIS deployment's verdict on this body, so the row stops
  // being offered on this lane — but it is recorded as a refusal rather than as
  // a defect of the row, because a body limit is a deployment's own setting and
  // the same bytes may be acceptable elsewhere. `skipped` is reserved for a row
  // no deployment could take.
  it('records a row the deployment refuses on its merits as refused, not skipped', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    const result = await run({ sendBatch: () => Promise.reject(new RemoteRequestError(400)) });

    expect(attempted(result).skipped).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL).refused)).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL).skipped)).toBe(0);
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
    expect(ledger((db) => db.historySync.counts(ALL))).toMatchObject({
      sent: 1,
      refused: 1,
      skipped: 0,
    });
  });

  // The other half of the split. A body this client refused to SEND reached no
  // deployment, so no deployment gave a verdict on it — it fails identically
  // everywhere, and re-attaching must not resurrect it.
  it('records a body this client would not send as skipped, not refused', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    const result = await run({
      sendBatch: () => Promise.reject(new RemoteRequestInvalid('/v1/audit-events', undefined)),
    });

    expect(attempted(result).skipped).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL).skipped)).toBe(2);
    expect(ledger((db) => db.historySync.counts(ALL).refused)).toBe(0);

    // And it survives a change of deployment, where a refusal would not.
    ledger((db) => {
      db.historySync.rearmFor('other-fingerprint', ALL);
    });
    expect(ledger((db) => db.historySync.counts(ALL).skipped)).toBe(2);
  });

  // A claim says a row is being sent right now. Nothing but this pass clears
  // one, so a pass that ends — however it ends — must not leave any behind.
  it('leaves no row claimed when the pass is over', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    seedCaptures([{ id: 'cap-1' }]);

    // BOTH lanes' seams, or the unsupplied one builds a real client and the send
    // never happens — which would leave nothing claimed for the wrong reason.
    await run({
      sendBatch: () => Promise.reject(new RemoteRequestError(400)),
      sendCaptures: () => Promise.reject(new RemoteRequestError(400)),
    });

    expect(ledger((db) => db.historySync.partition().inProgress)).toBe(0);
  });

  // The sweep, and why it ships with the claim rather than after it. A pass
  // killed mid-batch leaves its claim behind, and the capture read filters on
  // the claim being absent — so without this, one abandoned pass removes those
  // rows from every future page permanently.
  it('sweeps a claim an abandoned pass left behind, and offers the capture again', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([{ id: 'cap-1' }]);
    // Older than the staleness window, which is what marks it as belonging to a
    // pass that is gone rather than to a live sibling.
    ledger((db) => {
      db.historySync.claimRows(['cap-1'], T0 - 10 * 60_000);
    });
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);

    const sent: string[] = [];
    await run({
      sendBatch: (events) => Promise.resolve({ settled: events.length }),
      sendCaptures: (events) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toHaveLength(1);
    expect(ledger((db) => db.historySync.partition().inProgress)).toBe(0);
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

  // The design collision this whole describe block exists to close: a human
  // grants existing-history consent WHILE `aka attach` is pointing the
  // machine at the new deployment, and `seedCaptureBacklogOwed` marks the
  // pre-attach backlog owed at that instant — before the drain has run even
  // once under the new deployment. The very first pass under it sees the
  // fingerprint changed and, until this fix, wiped that grant's own markers
  // before ever reading them: the CLI's printed "sent in the background"
  // would have been false.
  it('keeps a backlog grant made while attaching TO the new deployment', async () => {
    attach({ grantFor: ENDPOINT });
    await run({ sendBatch: sendBatchOk }); // one pass under A: records A's fingerprint

    // A capture already on disk before either attach — genuinely pre-attach,
    // and deliberately NOT marked owed by seeding it directly rather than
    // through seedCaptures, which simulates a live forward instead.
    const db1 = openLocalDatabase(dataDirOf(home));
    try {
      db1.auditEvents.ensureSessionRoot('cap-session', new Date(T0 - 172_800_000).toISOString());
      db1.auditEvents.insertAuditEvent({
        id: 'cap-pre',
        eventType: 'prompt',
        rootSessionId: 'cap-session',
        parentId: 'cap-session',
        startedAt: new Date(T0 - 86_400_000).toISOString(),
        content: 'text of a pre-attach prompt',
        contentHash: 'b'.repeat(64),
        attributes: { source_tool: 'claude-code' },
      });
    } finally {
      db1.close();
    }

    // `aka attach --url OTHER_ENDPOINT`: points the machine at B and grants
    // existing-history consent for B, in that order — settings first, then
    // the backfill, exactly as attach.ts orders the two calls.
    const attachedToB = '2026-08-26T00:00:00.000Z';
    applyOnboarding(
      {
        controlPlane: { endpoint: OTHER_ENDPOINT, attachedAt: attachedToB },
        historySyncConsent: {
          acknowledgedAt: attachedToB,
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
      mintedAt: attachedToB,
    });
    const db2 = openLocalDatabase(dataDirOf(home));
    try {
      db2.historySync.markCaptureBacklogOwed(Date.parse(attachedToB));
    } finally {
      db2.close();
    }

    // The drain's FIRST pass under B — the one that discovers the fingerprint
    // changed and, before this fix, disowned the grant above before this
    // point was ever reached. Both lanes need their own sink, or the capture
    // lane falls through to the real transport and the pass reports
    // 'unreachable' instead of exercising what this test is about.
    const captured: IngestEvent[] = [];
    await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events: readonly IngestEvent[]) => {
        captured.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    });

    // The wire id is a derived uuid, not the row's own — content is what
    // proves it was THIS row, sent with the text a v3 grant promises.
    expect(captured.map((c) => c.content)).toEqual(['text of a pre-attach prompt']);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
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

describe('runHistorySync — the backlog boundary under a pinned connection', () => {
  // The drain reads the settings in force through the default managed read,
  // which takes no override, so a pinned machine is simulated end to end: an
  // administrator's file is written and the default read pointed at it. Where
  // the file sits is immaterial once the read is pointed at it.
  const pin = (values: ManagedSettingsValues): void => {
    const file = join(home, MANAGED_SETTINGS_FILENAME);
    writeFileSync(file, JSON.stringify({ specVersion: 1, values }));
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
  };
  // Back to no administrator, which is what the shared setup installs for
  // every other case in the package.
  afterEach(() => {
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
  });

  const rootAt = (id: string, iso: string): void => {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot(id, iso);
    } finally {
      db.close();
    }
  };

  /** `aka attach --url <endpoint>` at `at`: settings first, then the credential. */
  const enrol = (endpoint: string, at: string): void => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint, attachedAt: at },
        historySyncConsent: {
          acknowledgedAt: at,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint,
        },
      },
      home,
    );
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint,
      apiKey: FIXTURE,
      mintedAt: at,
    });
  };

  const drainSending = async (): Promise<string[]> => {
    const sent: string[] = [];
    await run({
      sendBatch: (events: readonly RecordAuditEventRequest[]) => {
        for (const e of events) sent.push(e.id);
        return Promise.resolve({ settled: events.length });
      },
    });
    return sent;
  };

  it('starts a moved pin’s backlog at the enrolment, not at the earlier deployment’s attach', async () => {
    // Attached to the first deployment at AT, with a pass under it on record.
    attach({ grantFor: ENDPOINT });
    await run({ sendBatch: sendBatchOk });

    const enrolledAt = '2026-08-24T12:00:00.000Z';
    // After the first attach and before the enrolment below: the new
    // deployment has seen none of it, and no live path will send it there.
    rootAt('s-between', '2026-08-24T11:00:00.000Z');
    // After the enrolment: the new deployment's live path owns it.
    rootAt('s-after', '2026-08-24T13:00:00.000Z');

    // The administrator moves the fleet, and this machine enrols with the new
    // deployment: its connection echoes the pin exactly.
    pin({ runMode: 'attached', controlPlane: { endpoint: OTHER_ENDPOINT } });
    enrol(OTHER_ENDPOINT, enrolledAt);

    expect(await drainSending()).toEqual(['s-between']);
  });

  it('starts an enrolment’s backlog at the enrolment where its connection echoes the pin', async () => {
    // A machine that was never attached, enrolling under a fleet pin. Without
    // a kept record the first boundary lands wherever the first pass happens.
    const enrolledAt = '2026-08-24T12:00:00.000Z';
    rootAt('s-before', '2026-08-24T11:00:00.000Z');
    rootAt('s-after', '2026-08-24T13:00:00.000Z');

    pin({ runMode: 'attached', controlPlane: { endpoint: ENDPOINT } });
    enrol(ENDPOINT, enrolledAt);

    expect(await drainSending()).toEqual(['s-before']);
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

  // A row COUNT is not a size on this lane: `content` is unbounded, so a page of
  // a hundred is anywhere from a few kilobytes to several megabytes. A body the
  // far side refuses comes back 413, which is terminal for those rows until the
  // machine points at a different deployment — so the split has to happen here.
  it('splits a page by BYTES, not just by row count', async () => {
    attach({ grantFor: ENDPOINT });
    const big = 'x'.repeat(600 * 1024);
    seedCaptures([
      { id: 'cap-1', content: big },
      { id: 'cap-2', content: big },
      { id: 'cap-3', content: big },
    ]);

    const requests: number[][] = [];
    await run({
      sendBatch: (events) => Promise.resolve({ settled: events.length }),
      sendCaptures: (events) => {
        requests.push(events.map((e) => e.content.length));
        return Promise.resolve({ settled: events.length });
      },
    });

    // 1.8 MiB of text cannot ride in one request under a 1 MiB ceiling.
    expect(requests.length).toBeGreaterThan(1);
    for (const sizes of requests) {
      expect(sizes.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(1024 * 1024);
    }
    // And every row still went.
    expect(requests.flat()).toHaveLength(3);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

  // A row larger than the whole budget cannot be made to fit by any batching,
  // and this read has no cursor — so left alone it would head every future page
  // for ever and the lane would stall behind it.
  it('gives up on a capture too large to ride at all, and sends the rest', async () => {
    attach({ grantFor: ENDPOINT });
    seedCaptures([
      { id: 'cap-huge', content: 'x'.repeat(2 * 1024 * 1024) },
      { id: 'cap-small', content: 'a modest prompt' },
    ]);

    const sent: string[] = [];
    await run({
      sendBatch: (events) => Promise.resolve({ settled: events.length }),
      sendCaptures: (events) => {
        for (const e of events) sent.push(e.content);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(sent).toEqual(['a modest prompt']);
    // Terminal, and named: this machine cannot express the row, so no change of
    // deployment frees it.
    expect(ledger((db) => db.historySync.counts(ALL).capturesSkipped)).toBe(1);
    expect(ledger((db) => db.historySync.pendingCaptureRows(10, ALL))).toEqual([]);
  });

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

// A SCOPED attachment: the drain sends only rows stamped with an enrolled
// repository key. See `credentialRead` at the top of the file for how these
// cases reach scoped mode.
describe('runHistorySync — a scoped attachment', () => {
  const WORK = 'github.com/acme/work';
  const OTHER_WORK = 'github.com/acme/other';
  const PERSONAL = 'github.com/someone/dotfiles';

  const SCOPED_CREDENTIAL = {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: FIXTURE,
    mintedAt: AT,
  } satisfies AttachedCredentialV2;

  afterEach(() => {
    credentialRead.value = undefined;
  });

  /** Rewrite the enrolled set, the way an enroll or an unenroll will. */
  const enroll = (keys: readonly string[]): void => {
    applyOnboarding(
      {
        attachmentScope: {
          endpoint: ENDPOINT,
          entries: keys.map((identity) => ({ kind: 'repo', identity, enrolledAt: AT })),
        },
      },
      home,
    );
  };

  /** Attached with a history grant, in SCOPED mode, with `keys` enrolled. */
  const attachScoped = (keys: readonly string[]): void => {
    attach({ grantFor: ENDPOINT });
    enroll(keys);
    credentialRead.value = { usable: true, credential: SCOPED_CREDENTIAL };
  };

  /**
   * A root and an llm_call leaf, each stamped with the key its producer
   * derived, or with none. Recorded before the attachment (AT), inside the
   * structural lane's backlog.
   */
  const seedKeyedSession = (
    id: string,
    offsetMs: number,
    keys: { root?: string; leaf?: string },
  ): void => {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      const startedAt = T0 - 86_400_000 + offsetMs;
      db.auditEvents.insertAuditEvent({
        id,
        eventType: 'session',
        startedAt: new Date(startedAt).toISOString(),
        ...(keys.root === undefined ? {} : { attributes: { scope_key: keys.root } }),
      });
      db.auditEvents.insertAuditEvent({
        id: `${id}-llm`,
        eventType: 'llm_call',
        rootSessionId: id,
        parentId: id,
        startedAt: new Date(startedAt + 1_000).toISOString(),
        ...(keys.leaf === undefined ? {} : { attributes: { scope_key: keys.leaf } }),
      });
    } finally {
      db.close();
    }
  };

  /**
   * A row's delivery columns, read straight off the table: through a ledger
   * read, which filters, an unsent personal row and an absent one look alike.
   */
  const delivery = (id: string): { syncedAt: number | null; owed: number | null } | undefined => {
    const raw = new DatabaseSync(dbPathOf(home));
    try {
      const row = raw
        .prepare('SELECT synced_at, outbox_owed FROM audit_events WHERE id = ?')
        .get(id) as { synced_at: number | null; outbox_owed: number | null } | undefined;
      return row === undefined ? undefined : { syncedAt: row.synced_at, owed: row.outbox_owed };
    } finally {
      raw.close();
    }
  };

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

  /**
   * A pass with a one-second budget whose clock moves only when a batch is sent.
   * The batch carrying `nearDeadline` leaves the clock 10 ms short of the pass
   * deadline, past the structural lane's slice; the batch carrying
   * `pastDeadline` runs `atDeadline`, when a case gives one, and moves the
   * clock past the deadline. `sleep` does not advance it, so nothing else
   * spends the budget, and each case decides which rows were sent when time
   * ran out.
   *
   * Traced against the drain, with those two the only sessions in scope when
   * the pass reads its pages: the first structural run sends `nearDeadline`'s
   * session and stops at the slice, which is no interruption while the pass
   * deadline is still ahead; the capture lane finds nothing; the second
   * structural run reads a page holding only `pastDeadline`'s session, sends
   * it, and returns 'ok' when it next checks the time, without reading another
   * page. So the pass reaches its end-of-pass check past the deadline, and that
   * check alone decides the outcome, whatever the drain's page size.
   */
  const passRunningOutOfTime = async (
    nearDeadline: string,
    pastDeadline: string,
    opts: {
      openStore?: NonNullable<Parameters<typeof runHistorySync>[0]['openStore']>;
      atDeadline?: () => void;
    } = {},
  ): Promise<{ pass: HistorySyncResult; sent: string[] }> => {
    let clock = T0;
    const sent: string[] = [];
    const result = await run({
      passBudgetMs: 1_000,
      now: () => clock,
      sleep: () => Promise.resolve(),
      sendBatch: (events) => {
        sent.push(...events.map((e) => e.id));
        if (events.some((e) => e.id === nearDeadline)) clock = T0 + 990;
        if (events.some((e) => e.id === pastDeadline)) {
          opts.atDeadline?.();
          clock = T0 + 5_000;
        }
        return Promise.resolve({ settled: events.length });
      },
      sendCaptures: (events) => Promise.resolve({ settled: events.length }),
      ...(opts.openStore === undefined ? {} : { openStore: opts.openStore }),
    });
    return { pass: attempted(result), sent };
  };

  // THE STALL, at the drain. Thirty older personal sessions head every page of
  // twenty-five, and none is ever stamped (they stay eligible for the day their
  // repository is enrolled), so a drain filtering pages in memory would re-read
  // them for ever and never reach the enrolled session.
  it('sends an enrolled session from behind thirty older personal ones', async () => {
    attachScoped([WORK]);
    for (let i = 0; i < 30; i += 1) {
      seedKeyedSession(`p-${String(i)}`, i * 60_000, { root: PERSONAL, leaf: PERSONAL });
    }
    seedKeyedSession('w-1', 31 * 60_000, { root: WORK, leaf: WORK });
    const l = lanes();

    const result = await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(attempted(result).outcome).toBe('ok');
    expect(l.structural.map((e) => e.id)).toEqual(['w-1', 'w-1-llm']);
    // Not stamped with any sentinel either: delivered, skipped and refused are
    // all terminal on this lane, and these rows must stay eligible.
    expect(delivery('p-0')).toEqual({ syncedAt: null, owed: null });
    expect(delivery('p-29-llm')).toEqual({ syncedAt: null, owed: null });
    // The local scope key never leaves the machine.
    expect(JSON.stringify(l.structural)).not.toContain('scope_key');
    // And the pass counts only its scope's rows. The sixty personal rows it left
    // are no backlog of this scope's, so nothing is pending, and the state file
    // can read complete.
    expect(attempted(result).counts).toMatchObject({ pending: 0, sent: 2 });
    expect(attempted(result).countsScope).toBe('scoped');
  });

  it('sends an enrolled capture from behind a full batch of older personal ones', async () => {
    attachScoped([WORK]);
    seedCaptures([
      ...Array.from({ length: 101 }, (_, i) => ({
        id: `cap-p-${String(i)}`,
        scopeKey: PERSONAL,
        atMs: T0 - 3_600_000 + i,
      })),
      { id: 'cap-w', scopeKey: WORK, atMs: T0 - 3_000_000 },
    ]);
    const l = lanes();

    const result = await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-w']);
    // Owed only in scope: the probe counts in-scope captures only, so a marker
    // on a personal capture does not hold `capturesPending` true.
    expect(attempted(result).capturesPending).toBe(false);
    expect(delivery('cap-p-0')).toEqual({ syncedAt: null, owed: 1 });
  });

  // A structural row goes only when its own key AND its root's key are enrolled:
  // the receiver's foreign keys are real and it stubs no root. Roots and leaves
  // are stamped from different places (the directory a session started in, each
  // record's own cwd), possibly by different builds, so every pairing turns up
  // in a real store.
  it('sends a structural row only when it and its root are both enrolled', async () => {
    attachScoped([WORK]);
    seedKeyedSession('keyless-root', 0, { leaf: WORK });
    seedKeyedSession('personal-root', 60_000, { root: PERSONAL, leaf: WORK });
    seedKeyedSession('keyless-leaf', 120_000, { root: WORK });
    seedKeyedSession('personal-leaf', 180_000, { root: WORK, leaf: PERSONAL });
    seedKeyedSession('both', 240_000, { root: WORK, leaf: WORK });
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.structural.map((e) => e.id)).toEqual([
      'keyless-leaf',
      'personal-leaf',
      'both',
      'both-llm',
    ]);

    // And the lane does not stall on what it left: the next pass finds nothing
    // in scope and offers nothing.
    let offered = 0;
    await run({
      sendBatch: (events) => {
        offered += events.length;
        return Promise.resolve({ settled: events.length });
      },
      sendCaptures: l.sendCaptures,
    });
    expect(offered).toBe(0);
  });

  // Rows written before stamping carry no key, and no key is never in scope,
  // whatever repository they came from.
  it('never sends a row recorded without a scope key', async () => {
    attachScoped([WORK]);
    seedRows(2);
    seedCaptures([{ id: 'cap-legacy' }]);
    const l = lanes();

    const result = await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.structural).toEqual([]);
    expect(l.captures).toEqual([]);
    expect(attempted(result).capturesPending).toBe(false);
    expect(delivery('cap-legacy')).toEqual({ syncedAt: null, owed: 1 });
  });

  // An older build's consent seed marks the whole backlog, scope or no scope:
  // the CLI and every plugin bundle their own copy, and the oldest one on the
  // machine may be the one that runs. The marker is not the guarantee; the
  // drain's scoped read is.
  it('sends nothing out of scope after an older build seeds the whole backlog', async () => {
    attachScoped([WORK]);
    seedCaptures([
      { id: 'cap-p', scopeKey: PERSONAL, owed: false },
      { id: 'cap-w', scopeKey: WORK, owed: false },
    ]);
    // FROZEN: the consent-time seed as builds before scoped attachment run it,
    // copied here on purpose so an edit to the live statement cannot change
    // what this replays.
    const raw = new DatabaseSync(dbPathOf(home));
    try {
      raw
        .prepare(
          `UPDATE audit_events SET outbox_owed = 1
            WHERE synced_at IS NULL
              AND event_type IN ('prompt', 'response', 'tool_use')
              AND started_at < :before`,
        )
        .run({ before: ALL });
    } finally {
      raw.close();
    }
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-w']);
    expect(delivery('cap-p')).toEqual({ syncedAt: null, owed: 1 });
  });

  // An unenroll that lands mid-pass takes that repository out of the very next
  // capture batch, not the next pass: settings are re-read before every batch.
  it('stops sending a repository unenrolled between two capture batches', async () => {
    attachScoped([WORK]);
    seedCaptures(
      Array.from({ length: 150 }, (_, i) => ({
        id: `cap-w-${String(i)}`,
        scopeKey: WORK,
        atMs: T0 - 3_600_000 + i,
      })),
    );
    const batches: number[] = [];

    await run({
      sendBatch: sendBatchOk,
      sendCaptures: (events) => {
        batches.push(events.length);
        // The unenroll, written while the first batch is in flight.
        enroll([]);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(batches).toEqual([100]);
    expect(delivery('cap-w-149')).toEqual({ syncedAt: null, owed: 1 });
  });

  // The structural lane's twin of the case above: the scope is re-read before
  // every page of sessions and every page of rows, so an unenroll that lands
  // mid-pass takes that repository out of the very next read rather than the
  // next pass. The first session is enrolled work, then thirty sessions of a
  // repository that is unenrolled while the first batch is in flight, then one
  // more of the repository that stays.
  it('stops sending a repository unenrolled between two structural pages', async () => {
    attachScoped([WORK, OTHER_WORK]);
    seedKeyedSession('w-first', 0, { root: WORK, leaf: WORK });
    for (let i = 0; i < 30; i += 1) {
      seedKeyedSession(`o-${String(i)}`, (i + 1) * 60_000, { root: OTHER_WORK, leaf: OTHER_WORK });
    }
    seedKeyedSession('w-last', 31 * 60_000, { root: WORK, leaf: WORK });
    const l = lanes();
    let unenrolled = false;

    await run({
      sendBatch: (events) => {
        l.structural.push(...events);
        // The unenroll, written while the first session's batch is in flight.
        if (!unenrolled) {
          unenrolled = true;
          enroll([WORK]);
        }
        return Promise.resolve({ settled: events.length });
      },
      sendCaptures: l.sendCaptures,
    });

    // The rest of the unenrolled repository's first page of sessions, and every
    // session after it, are held back; the repository that stayed still goes.
    expect(l.structural.map((e) => e.id)).toEqual([
      'w-first',
      'w-first-llm',
      'w-last',
      'w-last-llm',
    ]);
    expect(delivery('o-0')).toEqual({ syncedAt: null, owed: null });
    expect(delivery('o-29-llm')).toEqual({ syncedAt: null, owed: null });
  });

  // A MACHINE attachment has no scope to re-read: it reads settings once, at the
  // start of the pass, and a scope changing underneath it changes nothing.
  it('reads settings once on a machine attachment, whatever happens to the stored scope', async () => {
    attach({ grantFor: ENDPOINT });
    enroll([WORK]);
    for (let i = 0; i < 30; i += 1) {
      seedKeyedSession(`p-${String(i)}`, i * 60_000, { root: PERSONAL, leaf: PERSONAL });
    }
    seedKeyedSession('w-1', 31 * 60_000, { root: WORK, leaf: WORK });
    const l = lanes();
    let rewritten = false;
    settingsReads.count = 0;

    await run({
      sendBatch: (events) => {
        l.structural.push(...events);
        if (!rewritten) {
          rewritten = true;
          enroll([]);
        }
        return Promise.resolve({ settled: events.length });
      },
      sendCaptures: l.sendCaptures,
    });

    // Thirty-one sessions of a root and a leaf each, across two session pages.
    expect(l.structural).toHaveLength(62);
    expect(settingsReads.count).toBe(1);
  });

  // The enroll re-seed and the drain together: captures the live path refused
  // while their repository was out of scope become reachable once it is
  // enrolled and re-seeded, and only that repository's.
  it("sends a repository's capture backlog once the enroll re-seed marks it", async () => {
    attachScoped([]);
    seedCaptures([
      { id: 'cap-w', scopeKey: WORK, owed: false },
      { id: 'cap-p', scopeKey: PERSONAL, owed: false },
      // A marker an older build left on a personal capture.
      { id: 'cap-p-marked', scopeKey: PERSONAL },
    ]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });
    expect(l.captures).toEqual([]);

    enroll([WORK]);
    ledger((db) => db.historySync.markScopeCapturesOwed([WORK]));
    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-w']);
    expect(delivery('cap-p')).toEqual({ syncedAt: null, owed: null });
    expect(delivery('cap-p-marked')).toEqual({ syncedAt: null, owed: 1 });
  });

  // The fourth seed path: arming a deployment re-marks the consented backlog in
  // the same transaction as the wipe, scoped like the consent seed it repeats.
  it('re-marks only enrolled captures when it arms the deployment', async () => {
    attachScoped([WORK]);
    // Recorded before the grant and never marked, so only the re-mark can reach
    // them.
    const beforeGrant = Date.parse(AT) - 60_000;
    seedCaptures([
      { id: 'cap-w', scopeKey: WORK, owed: false, atMs: beforeGrant },
      { id: 'cap-p', scopeKey: PERSONAL, owed: false, atMs: beforeGrant },
    ]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-w']);
    expect(delivery('cap-p')).toEqual({ syncedAt: null, owed: null });
  });

  // The second look. The scoped read already excludes a personal capture; this
  // stands in a ledger whose read does not, and requires the drain's own
  // in-memory check to refuse it without stamping it.
  it('re-checks each capture before sending, and leaves what it refuses unstamped', async () => {
    attachScoped([WORK]);
    seedCaptures([
      { id: 'cap-p', scopeKey: PERSONAL, atMs: T0 - 3_600_000 },
      { id: 'cap-w', scopeKey: WORK, atMs: T0 - 3_000_000 },
    ]);
    const l = lanes();

    await run({
      sendBatch: l.sendBatch,
      sendCaptures: l.sendCaptures,
      openStore: (dir) => {
        const db = openLocalDatabase(dir);
        const unscoped = db.historySync.pendingCaptureRows.bind(db.historySync);
        db.historySync.pendingCaptureRows = (limit: number, before: number) =>
          unscoped(limit, before);
        return db;
      },
    });

    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-w']);
    expect(delivery('cap-p')).toEqual({ syncedAt: null, owed: 1 });
  });

  // THE REPOSITORY NAME A DRAINED CAPTURE CARRIES. The slug stored with a row is
  // the producer's, resolved from the session's directory, while its key can
  // name the repository of a file in another checkout. A capture whose live
  // forward failed, or that a seed marked, is rebuilt from that row, so the
  // drain applies the live forward's rewrite: the name sent is its own key's.
  it("sends a drained capture under its own key's repository name, keeping its id", async () => {
    attachScoped([WORK]);
    // A session in a personal checkout that wrote a file in the enrolled one.
    seedCaptures([{ id: 'cap-w', scopeKey: WORK, repo: 'dotfiles' }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.captures).toHaveLength(1);
    // The slug is replaced where it stands, and nothing else in the metadata
    // moves.
    expect(JSON.stringify(l.captures[0]?.metadata)).toBe(
      '{"sessionId":"cap-session","repo":"work"}',
    );
    // The id is reproduced from the row's session, content hash and file path,
    // never the slug, so the receiver's id-dedup still recognises a redelivery.
    expect(l.captures[0]?.id).toBe(captureWireId('cap-session', 'b'.repeat(64), null));
    // And the stamp goes by the row id: delivered, not left owed or skipped.
    expect(delivery('cap-w')?.syncedAt).toBeGreaterThanOrEqual(T0);
  });

  // A MACHINE attachment forwards everything, and a stored scope (left by an
  // earlier scoped attachment, or written by hand) changes nothing about it.
  it('ignores a stored scope on a machine attachment', async () => {
    attach({ grantFor: ENDPOINT });
    enroll([OTHER_WORK]);
    seedKeyedSession('w-1', 60_000, { root: WORK, leaf: WORK });
    // A stored slug that is not its key's last segment, so a rewrite would show.
    seedCaptures([{ id: 'cap-p', scopeKey: PERSONAL, repo: 'scratch' }]);
    const l = lanes();

    await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.structural.map((e) => e.id).sort()).toEqual(['cap-session', 'w-1', 'w-1-llm']);
    expect(l.captures.map((c) => c.content)).toEqual(['text of cap-p']);
    // The rebuilt body as it always was: the stored slug, byte for byte, not
    // the name of the repository its key points at.
    expect(JSON.stringify(l.captures[0]?.metadata)).toBe(
      '{"sessionId":"cap-session","repo":"scratch"}',
    );
  });

  // THE OUTCOME A SCOPED PASS REPORTS when its time runs out. Only what this
  // scope will send counts as left over: thirty personal sessions, and two whose
  // enrolled leaf sits under a root that is not enrolled (one with no key at
  // all), are rows no pass of this scope will ever offer. A pass that sent
  // everything it could has finished, and `aka sync-history --run` and the
  // dashboard would otherwise ask the user to run it again for nothing.
  it('reports a pass that runs out of time with only unreachable rows left as ok', async () => {
    attachScoped([WORK]);
    for (let i = 0; i < 30; i += 1) {
      seedKeyedSession(`p-${String(i)}`, i * 60_000, { root: PERSONAL, leaf: PERSONAL });
    }
    seedKeyedSession('keyless-root', 30 * 60_000, { leaf: WORK });
    seedKeyedSession('personal-root', 31 * 60_000, { root: PERSONAL, leaf: WORK });
    seedKeyedSession('w-0', 32 * 60_000, { root: WORK, leaf: WORK });
    seedKeyedSession('w-1', 33 * 60_000, { root: WORK, leaf: WORK });

    const { pass, sent } = await passRunningOutOfTime('w-0', 'w-1');

    expect(sent).toEqual(['w-0', 'w-0-llm', 'w-1', 'w-1-llm']);
    expect(pass.outcome).toBe('ok');
    expect(pass.counts).toMatchObject({ pending: 0, sent: 4 });
    expect(pass.countsScope).toBe('scoped');
  });

  // Its control: an enrolled row still unsent when time runs out is what an
  // interrupted pass is, and the scoped count still says so. The repository is
  // enrolled while the pass's last batch is in flight, after the drain read its
  // last page, so its session is left over for the end of the pass to find.
  it('still reports a pass interrupted when an enrolled row is left at its deadline', async () => {
    attachScoped([WORK]);
    for (let i = 0; i < 3; i += 1) {
      seedKeyedSession(`p-${String(i)}`, i * 60_000, { root: PERSONAL, leaf: PERSONAL });
    }
    seedKeyedSession('w-0', 3 * 60_000, { root: WORK, leaf: WORK });
    seedKeyedSession('w-1', 4 * 60_000, { root: WORK, leaf: WORK });
    seedKeyedSession('o-0', 5 * 60_000, { root: OTHER_WORK, leaf: OTHER_WORK });

    const { pass, sent } = await passRunningOutOfTime('w-0', 'w-1', {
      atDeadline: () => {
        enroll([WORK, OTHER_WORK]);
      },
    });

    expect(sent).toEqual(['w-0', 'w-0-llm', 'w-1', 'w-1-llm']);
    expect(pass.outcome).toBe('interrupted');
    // The session enrolled at the deadline, and none of the personal ones.
    expect(pass.counts.pending).toBe(2);
    expect(pass.countsScope).toBe('scoped');
  });

  // ONE READING OF THE SCOPE for everything a pass reports. The capture probe is
  // the only read that asks for one row, and the last such probe is the one in
  // the result. A pass counts once, at its end, for the outcome check and the
  // reported counts alike, and that one count must have been handed the probe's
  // very array.
  it('takes the outcome, the counts and the capture probe from one reading of the scope', async () => {
    attachScoped([WORK]);
    seedKeyedSession('w-0', 0, { root: WORK, leaf: WORK });
    seedKeyedSession('w-1', 60_000, { root: WORK, leaf: WORK });
    const countFilters: (readonly string[] | undefined)[] = [];
    const probeFilters: (readonly string[] | undefined)[] = [];

    const { pass, sent } = await passRunningOutOfTime('w-0', 'w-1', {
      openStore: (dir) => {
        const db = openLocalDatabase(dir);
        const counts = db.historySync.counts.bind(db.historySync);
        const pendingCaptureRows = db.historySync.pendingCaptureRows.bind(db.historySync);
        db.historySync.counts = (before: number, scopeKeys?: readonly string[]) => {
          countFilters.push(scopeKeys);
          return counts(before, scopeKeys);
        };
        db.historySync.pendingCaptureRows = (
          limit: number,
          before: number,
          scopeKeys?: readonly string[],
        ) => {
          if (limit === 1) probeFilters.push(scopeKeys);
          return pendingCaptureRows(limit, before, scopeKeys);
        };
        return db;
      },
    });

    // The batch that moves the clock past the deadline went, so the pass reached
    // its end-of-pass check past the deadline, with nothing left in scope.
    expect(sent).toEqual(['w-0', 'w-0-llm', 'w-1', 'w-1-llm']);
    expect(pass.outcome).toBe('ok');
    const reading = probeFilters.at(-1);
    expect(reading).toEqual([WORK]);
    expect(countFilters).toHaveLength(1);
    expect(countFilters[0]).toBe(reading);
  });

  // A MACHINE attachment counts everything recorded, a stored scope ignored, and
  // says that it did: the state file records it for `aka status`.
  it('counts everything recorded on a machine attachment, and says so', async () => {
    attach({ grantFor: ENDPOINT });
    enroll([WORK]);
    seedKeyedSession('p-1', 0, { root: PERSONAL, leaf: PERSONAL });
    const l = lanes();

    const result = await run({ sendBatch: l.sendBatch, sendCaptures: l.sendCaptures });

    expect(l.structural.map((e) => e.id)).toEqual(['p-1', 'p-1-llm']);
    expect(attempted(result).counts).toMatchObject({ pending: 0, sent: 2 });
    expect(attempted(result).countsScope).toBe('machine');
  });
});
