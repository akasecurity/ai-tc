import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  ATTACHED_IDENTITY_FILENAME,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  openLocalDatabase,
  readAttachedIdentity,
  recordValidatedWorkAccount,
  SETTINGS_FILENAME,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { IngestEvent, RecordAuditEventRequest } from '@akasecurity/schema';
import { agentKey, HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { readHistorySyncState } from '../../src/attached/history-state.ts';
import type { HistorySyncResult } from '../../src/attached/history-sync.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
import { runHistorySyncPass } from '../../src/attached/history-sync-entry.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// The history drain on a machine whose credential file really is a scoped (v2)
// one, read by the real reader, with no stand-in anywhere in this file. The
// scoped cases in the drain suite arm a mocked read; this one is what fails if
// the reader refuses the file, because the pass then never runs and reports
// `credential-unusable` instead.

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-08-24T10:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const T0 = Date.parse('2026-08-25T00:00:00.000Z');
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-history-scoped-cred-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
});

afterEach(() => {
  removeTree(home);
});

/** Attached with a history grant, a scoped credential, and one enrolled repository. */
function attachScoped(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      },
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
      },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(home), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    mintedAt: AT,
  });
}

/**
 * Two owed captures, one per repository. The personal one is owed too, the way
 * an older build's consent seed marks the whole backlog: the marker is not the
 * guarantee, the drain's scoped read is. Both land after the attachment and
 * outside the live path's grace window.
 */
function seedOwedCaptures(): void {
  const db = openLocalDatabase(dataDirOf(home));
  try {
    db.auditEvents.ensureSessionRoot('cap-session', new Date(T0 - 86_400_000).toISOString());
    const rows = [
      { id: 'cap-personal', scopeKey: PERSONAL_REPO, atMs: T0 - 3_600_000 },
      { id: 'cap-work', scopeKey: WORK_REPO, atMs: T0 - 3_000_000 },
    ];
    for (const row of rows) {
      db.auditEvents.insertAuditEvent({
        id: row.id,
        eventType: 'prompt',
        rootSessionId: 'cap-session',
        parentId: 'cap-session',
        startedAt: new Date(row.atMs).toISOString(),
        content: `text of ${row.id}`,
        contentHash: 'b'.repeat(64),
        attributes: { source_tool: 'claude-code', scope_key: row.scopeKey },
      });
      db.historySync.markCaptureOwed(row.id);
    }
  } finally {
    db.close();
  }
}

/** A row's delivery columns, read straight off the table. */
function delivery(id: string): { syncedAt: number | null; owed: number | null } | undefined {
  const raw = new DatabaseSync(dbPathOf(home));
  try {
    const row = raw
      .prepare('SELECT synced_at, outbox_owed FROM audit_events WHERE id = ?')
      .get(id) as { synced_at: number | null; outbox_owed: number | null } | undefined;
    return row === undefined ? undefined : { syncedAt: row.synced_at, owed: row.outbox_owed };
  } finally {
    raw.close();
  }
}

function attempted(result: Awaited<ReturnType<typeof runHistorySync>>): HistorySyncResult {
  if (!result.attempted) {
    throw new Error(`expected a pass to run, but it was skipped: ${result.reason}`);
  }
  return result;
}

describe('runHistorySync — a scoped credential read from disk', () => {
  it('sends the enrolled capture and leaves the personal one owed and unsent', async () => {
    attachScoped();
    seedOwedCaptures();
    const structural: RecordAuditEventRequest[] = [];
    const captures: IngestEvent[] = [];
    let clock = T0;

    const result = await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      now: () => clock,
      sleep: () => {
        clock += 1;
        return Promise.resolve();
      },
      random: () => 0,
      // Every sender is injected, so the pass builds no client of its own.
      sendBatch: (events) => {
        structural.push(...events);
        return Promise.resolve({ settled: events.length });
      },
      sendOne: (event) => {
        structural.push(event);
        return Promise.resolve();
      },
      sendCaptures: (events) => {
        captures.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(attempted(result).capturesPending).toBe(false);
    // Nothing this scope will send is left. The capture session's root carries
    // no key, so no scoped pass ever offers it, and no scoped count holds it.
    expect(attempted(result).counts.pending).toBe(0);
    expect(attempted(result).countsScope).toBe('scoped');
    expect(captures.map((c) => c.content)).toEqual(['text of cap-work']);
    // The capture session's root carries no key, and no key is never in scope.
    expect(structural).toEqual([]);
    expect(delivery('cap-work')?.syncedAt).toEqual(expect.any(Number));
    expect(delivery('cap-personal')).toEqual({ syncedAt: null, owed: 1 });
  });

  // The same machine through the entry every harness runs: the state file says
  // the drain is complete, counted through the scope, while a personal capture
  // stays owed and the keyless root stays unsent.
  it('records the drain complete, counted through the scope, with a personal capture still owed', async () => {
    attachScoped();
    seedOwedCaptures();
    let clock = T0;

    await expect(
      runHistorySyncPass(home, {
        now: () => clock,
        sleep: () => {
          clock += 1;
          return Promise.resolve();
        },
        random: () => 0,
        sendBatch: (events) => Promise.resolve({ settled: events.length }),
        sendCaptures: (events) => Promise.resolve({ settled: events.length }),
      }),
    ).resolves.toBe('ok');

    expect(readHistorySyncState(dataDirOf(home))).toMatchObject({
      phase: 'complete',
      pendingTotal: 0,
      countsScope: 'scoped',
    });
    expect(delivery('cap-personal')).toEqual({ syncedAt: null, owed: 1 });
  });
});

// The same drain once this attachment has learned a work account: rows stamped
// with that account's agent key are in its scope, re-derived before every page,
// so an opt-out, or an identity record that stops holding, takes them out of the
// next one. The consent re-mark still reads the stored entries alone.
describe('runHistorySync — rows stamped for a learned work account', () => {
  const ACCOUNT = `claude:${randomUUID()}`;
  const CREDENTIAL = {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    mintedAt: AT,
  } as const;

  /** The identity record for this credential, one learned account, and its agent key. */
  function learn(): string {
    writeAttachedIdentity(dataDirOf(home), {
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      tenantName: 'Acme',
      userEmail: ['member', 'example.test'].join('@'),
    });
    recordValidatedWorkAccount(dataDirOf(home), {
      endpoint: ENDPOINT,
      credential: CREDENTIAL,
      key: ACCOUNT,
    });
    const record = readAttachedIdentity(dataDirOf(home));
    if (!record?.workAccounts.some((entry) => entry.identity === ACCOUNT)) {
      throw new Error('the account was not learned');
    }
    const key = agentKey(record.scopeTag, ACCOUNT);
    if (key === undefined) throw new Error('no agent key was built');
    return key;
  }

  /** `count` prompt captures stamped `scopeKey`, `atMs` onwards, one millisecond apart. */
  function seed(
    prefix: string,
    scopeKey: string,
    count: number,
    atMs: number,
    owed: boolean,
  ): void {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot(`${prefix}-session`, new Date(atMs - 60_000).toISOString());
      for (let i = 0; i < count; i += 1) {
        const id = `${prefix}-${String(i)}`;
        db.auditEvents.insertAuditEvent({
          id,
          eventType: 'prompt',
          rootSessionId: `${prefix}-session`,
          parentId: `${prefix}-session`,
          startedAt: new Date(atMs + i).toISOString(),
          content: `text of ${id}`,
          contentHash: 'c'.repeat(64),
          attributes: { source_tool: 'claude-code', scope_key: scopeKey },
        });
        if (owed) db.historySync.markCaptureOwed(id);
      }
    } finally {
      db.close();
    }
  }

  /** The scope record on disk, edited raw, the way the opt-out command writes it. */
  function turnWorkSubscriptionsOff(): void {
    const file = join(settingsDirOf(home), SETTINGS_FILENAME);
    const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    const scope = settings.attachmentScope as Record<string, unknown>;
    writeFileSync(
      file,
      JSON.stringify({ ...settings, attachmentScope: { ...scope, workSubscriptions: 'off' } }),
    );
  }

  async function pass(
    sendCaptures: (events: readonly IngestEvent[]) => Promise<{ settled: number }>,
  ): Promise<HistorySyncResult> {
    let clock = T0;
    return attempted(
      await runHistorySync({
        base: home,
        settingsDir: settingsDirOf(home),
        dataDir: dataDirOf(home),
        now: () => clock,
        sleep: () => {
          clock += 1;
          return Promise.resolve();
        },
        random: () => 0,
        sendBatch: (events) => Promise.resolve({ settled: events.length }),
        sendOne: () => Promise.resolve(),
        sendCaptures,
      }),
    );
  }

  it('sends an owed capture stamped for a learned work account', async () => {
    attachScoped();
    seed('agent', learn(), 1, T0 - 3_600_000, true);
    const captures: IngestEvent[] = [];

    const result = await pass((events) => {
      captures.push(...events);
      return Promise.resolve({ settled: events.length });
    });

    expect(captures.map((c) => c.content)).toEqual(['text of agent-0']);
    expect(delivery('agent-0')?.syncedAt).toEqual(expect.any(Number));
    expect(result.capturesPending).toBe(false);
  });

  it('stops sending at the next batch once work subscriptions are turned off', async () => {
    attachScoped();
    seed('agent', learn(), 150, T0 - 3_600_000, true);
    const batches: number[] = [];

    await pass((events) => {
      batches.push(events.length);
      // The opt-out, written while the first batch is in flight.
      turnWorkSubscriptionsOff();
      return Promise.resolve({ settled: events.length });
    });

    expect(batches).toEqual([100]);
    expect(delivery('agent-149')).toEqual({ syncedAt: null, owed: 1 });
  });

  it('stops sending at the next batch once the identity record stops holding', async () => {
    attachScoped();
    seed('agent', learn(), 150, T0 - 3_600_000, true);
    const batches: number[] = [];

    await pass((events) => {
      batches.push(events.length);
      // A detach's sweep, or a re-attach by an older build, landing mid-pass.
      rmSync(join(dataDirOf(home), ATTACHED_IDENTITY_FILENAME), { force: true });
      return Promise.resolve({ settled: events.length });
    });

    expect(batches).toEqual([100]);
    expect(delivery('agent-149')).toEqual({ syncedAt: null, owed: 1 });
  });

  // The first pass on this store arms the deployment and re-marks the grant's
  // backlog, scoped like the consent seed it repeats. Neither capture below is
  // marked owed when the pass starts: the enrolled one is the control.
  it("re-marks only the stored entries' captures when it arms a deployment", async () => {
    attachScoped();
    const agentScoped = learn();
    seed('work-backlog', WORK_REPO, 1, Date.parse(AT) - 3_600_000, false);
    seed('agent-backlog', agentScoped, 1, Date.parse(AT) - 3_600_000, false);
    const captures: IngestEvent[] = [];

    await pass((events) => {
      captures.push(...events);
      return Promise.resolve({ settled: events.length });
    });

    expect(captures.map((c) => c.content)).toEqual(['text of work-backlog-0']);
    expect(delivery('agent-backlog-0')).toEqual({ syncedAt: null, owed: null });
  });
});

// Without a grant the pass still sends what the live path left owed, read through
// the keys it derives: an owed capture stamped with the agent key of an account
// enrolled by hand waits while the account is not enrolled and is sent once it is
// enrolled again.
describe('runHistorySync — an account enrolled by hand, without a history grant', () => {
  const ACCOUNT = `claude:${randomUUID()}`;

  function attachWithEntries(entries: readonly unknown[]): void {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
        attachmentScope: { endpoint: ENDPOINT, entries },
      },
      home,
      null,
    );
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 2,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      mintedAt: AT,
    });
  }

  function agentKeyOfAttached(): string {
    writeAttachedIdentity(dataDirOf(home), {
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      tenantName: 'Acme',
      userEmail: ['member', 'example.test'].join('@'),
    });
    const record = readAttachedIdentity(dataDirOf(home));
    const key = record === undefined ? undefined : agentKey(record.scopeTag, ACCOUNT);
    if (key === undefined) throw new Error('no agent key was built');
    return key;
  }

  function seedOwed(scopeKey: string, startedAtMs: number): void {
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot(
        'owed-session',
        new Date(startedAtMs - 60_000).toISOString(),
      );
      db.auditEvents.insertAuditEvent({
        id: 'owed-0',
        eventType: 'prompt',
        rootSessionId: 'owed-session',
        parentId: 'owed-session',
        startedAt: new Date(startedAtMs).toISOString(),
        content: 'text of owed-0',
        contentHash: 'c'.repeat(64),
        attributes: { source_tool: 'claude-code', scope_key: scopeKey },
      });
      db.historySync.markCaptureOwed('owed-0');
    } finally {
      db.close();
    }
  }

  async function pass(): Promise<IngestEvent[]> {
    const captures: IngestEvent[] = [];
    let clock = T0;
    await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      now: () => clock,
      sleep: () => {
        clock += 1;
        return Promise.resolve();
      },
      random: () => 0,
      sendBatch: (events) => Promise.resolve({ settled: events.length }),
      sendOne: () => Promise.resolve(),
      sendCaptures: (events) => {
        captures.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    });
    return captures;
  }

  const entry = { kind: 'account', identity: ACCOUNT, enrolledAt: AT, codingAgents: true };

  it('sends an owed capture once the account is enrolled again, and not while it is not', async () => {
    attachWithEntries([]);
    seedOwed(agentKeyOfAttached(), T0 - 3_600_000);

    expect(await pass()).toEqual([]);
    expect(delivery('owed-0')).toEqual({ syncedAt: null, owed: 1 });

    attachWithEntries([entry]);
    expect((await pass()).map((c) => c.content)).toEqual(['text of owed-0']);
    expect(delivery('owed-0')?.syncedAt).toEqual(expect.any(Number));
  });

  it('sends none recorded before the machine attached', async () => {
    attachWithEntries([entry]);
    seedOwed(agentKeyOfAttached(), Date.parse(AT) - 3_600_000);

    expect(await pass()).toEqual([]);
    expect(delivery('owed-0')).toEqual({ syncedAt: null, owed: 1 });
  });
});
