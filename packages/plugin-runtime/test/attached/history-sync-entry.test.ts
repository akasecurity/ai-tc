import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { takeBlockedAttempts } from '../../../../test/setup/no-network.ts';
import {
  historySyncStatePath,
  readHistorySyncState,
  writeHistorySyncState,
} from '../../src/attached/history-state.ts';
import { runHistorySyncPass } from '../../src/attached/history-sync-entry.ts';

const ENDPOINT = 'https://plane.example.test';
const AT = '2026-08-24T10:00:00.000Z';
const FIXTURE = 'placeholder';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-history-entry-'));
});

afterEach(() => {
  removeTree(home);
});

const attachWithGrant = (): void => {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      },
    },
    home,
  );
  writeControlPlaneCredential(settingsDirOf(home), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: FIXTURE,
    mintedAt: AT,
  });
};

describe('runHistorySyncPass', () => {
  // The child runs detached with stdio ignored: a rejection would be an
  // unhandled rejection nobody ever reads.
  it('never throws on a machine that was never attached', async () => {
    await expect(runHistorySyncPass(home)).resolves.toBeUndefined();
  });

  // Writing state for a pass that was never made would have status describe a
  // deployment this machine never called — and would re-create a file a detach
  // had just removed.
  it('records nothing when no pass was made', async () => {
    await runHistorySyncPass(home);
    expect(existsSync(historySyncStatePath(dataDirOf(home)))).toBe(false);
  });

  it('leaves an existing record alone when no pass was made', async () => {
    const dir = dataDirOf(home);
    const db = openLocalDatabase(dir);
    db.close();
    writeHistorySyncState(dir, {
      phase: 'complete',
      lastOutcome: 'ok',
      lastPassAtMs: 1_000,
      sentTotal: 7,
      pendingTotal: 0,
      skippedTotal: 0,
      startedAtMs: 500,
      completedAtMs: 1_000,
    });

    await runHistorySyncPass(home);

    expect(readHistorySyncState(dir)).toMatchObject({ sentTotal: 7, lastPassAtMs: 1_000 });
  });

  it('records progress once a pass has run', async () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: ENDPOINT,
        },
      },
      home,
    );
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: FIXTURE,
      mintedAt: AT,
    });

    // An empty store: nothing to send, so the drain is complete on its first
    // pass — which is the state a freshly installed machine is genuinely in.
    const db = openLocalDatabase(dataDirOf(home));
    db.close();

    await runHistorySyncPass(home);

    const state = readHistorySyncState(dataDirOf(home));
    expect(state).toMatchObject({ phase: 'complete', lastOutcome: 'ok', pendingTotal: 0 });
    // The first pass that ran is when this machine started, and it is stamped.
    expect(state?.startedAtMs).not.toBeNull();
    expect(state?.completedAtMs).not.toBeNull();
  });

  // completedAtMs is the FIRST moment this machine owed the deployment nothing,
  // and it has to survive `done` going false again. Under v1 that never happened
  // — the structural lane only ever drained — but the capture lane's subject
  // grows with every failed live send, so a later capture flips `done` back and
  // the old write cleared the pin, re-stamping it on the next catch-up. A
  // consumer reading "when this machine first caught up" then got the most
  // recent catch-up instead.
  it('keeps the first completedAtMs when a later pass has work again', async () => {
    attachWithGrant();
    const db = openLocalDatabase(dataDirOf(home));
    db.close();

    await runHistorySyncPass(home);
    const first = readHistorySyncState(dataDirOf(home))?.completedAtMs;
    expect(first).not.toBeNull();

    // A capture the live path never delivered, recorded after the attachment and
    // outside the grace window: the next pass has work, so `done` is false.
    const owed = openLocalDatabase(dataDirOf(home));
    try {
      owed.auditEvents.ensureSessionRoot('s-1', AT);
      owed.auditEvents.insertAuditEvent({
        id: 's-1-prompt',
        eventType: 'prompt',
        rootSessionId: 's-1',
        parentId: 's-1',
        startedAt: new Date(Date.parse(AT) + 60_000).toISOString(),
        content: 'a prompt nobody delivered',
        contentHash: 'c'.repeat(64),
        attributes: { source_tool: 'claude-code' },
      });
    } finally {
      owed.close();
    }

    // This pass has work, so unlike the first it really tries to send — and the
    // no-network guard refuses it, which is the point: the row stays owed, so
    // `done` is false and the false branch of completedAtMs is the one taken.
    // The refusal is drained deliberately (the guard's one documented seam),
    // because it is provoked rather than incidental.
    await runHistorySyncPass(home);
    expect(takeBlockedAttempts().length).toBeGreaterThan(0);
    const after = readHistorySyncState(dataDirOf(home));

    // The pass found work, so the phase flapped back...
    expect(after?.phase).toBe('filling');
    // ...and the pin did not move.
    expect(after?.completedAtMs).toBe(first);
  });
});
