import { mkdtempSync, rmSync } from 'node:fs';
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
import type { RecordAuditEventRequest } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runHistorySync } from '../../src/attached/history-sync.ts';

const ENDPOINT = 'https://plane.example.test';
const OTHER_ENDPOINT = 'https://other.example.test';
const AT = '2026-08-24T10:00:00.000Z';
const FIXTURE = 'placeholder';
const T0 = Date.parse('2026-08-25T00:00:00.000Z');

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
const run = (over: Partial<Parameters<typeof runHistorySync>[0]> = {}) => {
  let clock = T0;
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

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-history-pass-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('runHistorySync — passes that are never made', () => {
  // Null is NOT an outcome: it means nothing was attempted, and the caller
  // writes no state for it. Recording one would have status describe a
  // deployment this machine never called.
  it('makes no pass on an unattached machine', async () => {
    await expect(run()).resolves.toBeNull();
  });

  it('makes no pass without a grant', async () => {
    attach();
    seedRows();
    await expect(run()).resolves.toBeNull();
  });

  it('makes no pass when the grant names another deployment', async () => {
    attach({ grantFor: OTHER_ENDPOINT });
    seedRows();
    await expect(run()).resolves.toBeNull();
  });

  it('makes no pass without a usable credential', async () => {
    attach({ grantFor: ENDPOINT, credential: false });
    seedRows();
    await expect(run()).resolves.toBeNull();
  });

  // Two drains would send the same rows and the far side would settle it, so
  // this saves request budget rather than correctness — but it should still hold.
  it('makes no pass while another process holds the claim', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    ledger((db) => db.historySync.claim(999_999, 'another-host', T0, 60_000));

    await expect(run()).resolves.toBeNull();
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
        return Promise.resolve();
      },
    });

    expect(result?.outcome).toBe('ok');
    expect(result?.sent).toBe(4);
    expect(sent).toEqual(['s-0', 's-0-llm', 's-1', 's-1-llm']);
    expect(ledger((db) => db.historySync.counts())).toMatchObject({ pending: 0, sent: 4 });
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
        return Promise.resolve();
      },
    });

    expect(sent.indexOf('s-0')).toBeLessThan(sent.indexOf('s-0-llm'));
  });

  it('leaves the claim free for the next pass', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    await run({ sendBatch: () => Promise.resolve() });

    expect(ledger((db) => db.historySync.lease()?.ownerPid)).toBeNull();
  });

  it('does nothing on a second pass once everything has gone', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows();
    await run({ sendBatch: () => Promise.resolve() });

    const again = await run({
      sendBatch: () => Promise.reject(new Error('should not be called')),
    });
    expect(again?.sent).toBe(0);
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

    expect(result?.outcome).toBe('refused');
    expect(calls).toBe(1);
    expect(ledger((db) => db.historySync.counts().sent)).toBe(0);
  });

  // Everything unacknowledged stays pending: an outage must never become data
  // loss, which is the whole reason the stamp comes after the ack.
  it('leaves everything pending when the deployment is unreachable', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(2);

    const result = await run({ sendBatch: () => Promise.reject(new Error('socket hang up')) });

    expect(result?.outcome).toBe('unreachable');
    expect(ledger((db) => db.historySync.counts())).toMatchObject({ pending: 4, sent: 0 });
  });

  it('retries a failure that might not repeat before giving up', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    let calls = 0;

    await run({
      sendBatch: () => {
        calls += 1;
        return calls < 3 ? Promise.reject(new Error('transient')) : Promise.resolve();
      },
    });

    // Both rows ride ONE request, so the ladder runs once: two transient
    // failures, then a success that lands the whole batch.
    expect(calls).toBe(3);
    expect(ledger((db) => db.historySync.counts().sent)).toBe(2);
  });

  // A body the deployment understood and rejected cannot be fixed by sending it
  // again, so it becomes a counted skip rather than an endless retry.
  it('permanently skips a row the deployment refuses on its merits', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);

    const result = await run({ sendBatch: () => Promise.reject(new RemoteRequestError(400)) });

    expect(result?.skipped).toBe(2);
    expect(ledger((db) => db.historySync.counts().skipped)).toBe(2);
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
          : Promise.resolve(),
    });

    expect(result?.sent).toBe(1);
    expect(result?.skipped).toBe(1);
    expect(ledger((db) => db.historySync.counts())).toMatchObject({ sent: 1, skipped: 1 });
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
      sendBatch: () => Promise.resolve(),
    });

    expect(result?.outcome).toBe('interrupted');
    expect(ledger((db) => db.historySync.counts().pending)).toBeGreaterThan(0);
  });
});

describe('runHistorySync — changing deployment', () => {
  // Delivery is a fact about ONE recipient. Rows sent to the deployment a
  // machine has left are undelivered as far as the next one is concerned.
  it('re-arms rows delivered to a previous deployment', async () => {
    attach({ grantFor: ENDPOINT });
    seedRows(1);
    await run({ sendBatch: () => Promise.resolve() });
    expect(ledger((db) => db.historySync.counts())).toMatchObject({ pending: 0, sent: 2 });

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
        return Promise.resolve();
      },
    });

    expect(sent).toEqual(['s-0', 's-0-llm']);
  });
});
