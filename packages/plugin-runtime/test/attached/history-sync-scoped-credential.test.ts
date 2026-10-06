import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  openLocalDatabase,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { IngestEvent, RecordAuditEventRequest } from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { HistorySyncResult } from '../../src/attached/history-sync.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
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
    expect(captures.map((c) => c.content)).toEqual(['text of cap-work']);
    // The capture session's root carries no key, and no key is never in scope.
    expect(structural).toEqual([]);
    expect(delivery('cap-work')?.syncedAt).toEqual(expect.any(Number));
    expect(delivery('cap-personal')).toEqual({ syncedAt: null, owed: 1 });
  });
});
