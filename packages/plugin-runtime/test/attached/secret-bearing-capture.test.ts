/**
 * A whole-file capture of a dotenv file is recorded locally and never sent: not
 * by the live forward, and not by the outbox drain that re-offers undelivered
 * captures. A source file's capture, and a prompt, still go.
 */
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
import type { CaptureRecord } from '@akasecurity/plugin-sdk';
import { contentHashOf } from '@akasecurity/plugin-sdk';
import type {
  IngestAck,
  IngestBatch,
  IngestEvent,
  ResolvedAttachmentScope,
} from '@akasecurity/schema';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

const ENDPOINT = 'https://plane.example.test';
const CREDENTIAL = 'placeholder';
const AT = '2026-08-24T10:00:00.000Z';
const T0 = Date.parse('2026-08-25T00:00:00.000Z');
const OCCURRED = new Date(T0 - 3_600_000).toISOString();
const KEY = 'github.com/acme/api';
const MACHINE: ResolvedAttachmentScope = { mode: 'machine', keys: new Set<string>() };
const SCOPED: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set<string>([KEY]) };

// Built at runtime so no credential-shaped literal sits in the source.
const fakeToken = (): string => ['gh', 'p_'].join('') + 'a1B2c3D4e5F6'.repeat(3);
const VARIABLE = ['GITHUB', 'TOKEN'].join('_');
const DOTENV_TEXT = VARIABLE + '=' + fakeToken() + '\n';
const SOURCE_TEXT = 'export const value = ' + JSON.stringify(fakeToken()) + ';\n';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-secret-bearing-'));
  migratedStore.seed(dataDirOf(home));
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
    apiKey: CREDENTIAL,
    mintedAt: AT,
  });
});

afterEach(() => {
  removeTree(home);
});

const scannerCapture = (filePath: string, content: string): CaptureRecord => ({
  event: {
    id: `scan-${filePath}`,
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: OCCURRED,
    contentHash: contentHashOf(content),
    content,
    metadata: { filePath, wholeFile: true },
  },
  findings: [],
  scopeKey: KEY,
});

const promptCapture = (
  id: string,
  content: string,
  metadata?: CaptureRecord['event']['metadata'],
): CaptureRecord => ({
  event: {
    id,
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: OCCURRED,
    contentHash: contentHashOf(content),
    content,
    ...(metadata !== undefined ? { metadata } : {}),
  },
  findings: [],
  scopeKey: KEY,
});

const passthrough: ForwardPolicy = {
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
};

function client(ingestEvents: (batch: IngestBatch) => Promise<IngestAck>): AttachedClient {
  return {
    ingestEvents: vi.fn(ingestEvents),
    ingestInventory: () => Promise.resolve({}),
    recordAuditEvent: () => Promise.resolve(),
    recordAuditEvents: (events) => Promise.resolve({ accepted: events.length }),
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: () => Promise.resolve({}),
    recordConfigInventory: () => Promise.resolve({ accepted: 0 }),
  };
}

function gatewayWith(remote: AttachedClient, attachment: ResolvedAttachmentScope) {
  const local = new StandaloneDataGateway(dataDirOf(home));
  return new AttachedDataGateway({
    dataDir: dataDirOf(home),
    local,
    client: remote,
    readCachedBundle: () => Promise.resolve(null),
    forward: passthrough,
    attachment,
  });
}

// Every capture row in the local store, with the file it names.
const captureRows = (): { id: string; filePath: unknown }[] => {
  const db = new DatabaseSync(dbPathOf(home), { readOnly: true });
  try {
    const rows = db
      .prepare(
        `SELECT id, attributes FROM audit_events
          WHERE event_type IN ('code_change', 'prompt') ORDER BY id`,
      )
      .all() as { id: string; attributes: string | null }[];
    return rows.map((row) => ({
      id: row.id,
      filePath: (JSON.parse(row.attributes ?? '{}') as { file_path?: unknown }).file_path,
    }));
  } finally {
    db.close();
  }
};

describe.each([
  ['machine', MACHINE],
  ['scoped', SCOPED],
])('a dotenv snapshot on a %s attachment', (_name, attachment) => {
  it('is recorded locally and never reaches the live forward', async () => {
    const sent: IngestEvent[] = [];
    const remote = client((batch) => {
      sent.push(...batch.events);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    });
    const gateway = gatewayWith(remote, attachment);
    try {
      await gateway.recordCapture(scannerCapture('/repo/.env', DOTENV_TEXT));
      await gateway.recordCapture(scannerCapture('/repo/config/.env.local', DOTENV_TEXT + 'X=1\n'));
      await gateway.recordCapture(scannerCapture('/repo/src/app.ts', SOURCE_TEXT));
    } finally {
      await gateway.close();
    }

    expect(sent.map((e) => e.metadata?.filePath)).toEqual(['/repo/src/app.ts']);
    expect(JSON.stringify(sent)).not.toContain(VARIABLE);
    expect(captureRows().map((r) => r.filePath)).toEqual(
      expect.arrayContaining(['/repo/.env', '/repo/config/.env.local', '/repo/src/app.ts']),
    );
  });

  it('is never sent by the outbox drain, even under a drained kind and marked owed', async () => {
    const gateway = gatewayWith(
      client(() => Promise.reject(new Error('plane down'))),
      attachment,
    );
    try {
      // Filed as a prompt, a kind the drain selects and rebuilds, so the
      // snapshot check is the only thing that keeps it back.
      await gateway.recordCapture(
        promptCapture('prompt-env', DOTENV_TEXT, { filePath: '/repo/.env', wholeFile: true }),
      );
      await gateway.recordCapture(promptCapture('prompt-1', 'a prompt that was not delivered'));
    } finally {
      await gateway.close();
    }

    const db = openLocalDatabase(dataDirOf(home));
    try {
      for (const row of captureRows()) db.historySync.markCaptureOwed(row.id);
      db.historySync.markCaptureBacklogOwed(T0, attachment.mode === 'scoped' ? [KEY] : undefined);
    } finally {
      db.close();
    }

    const captured: IngestEvent[] = [];
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
        captured.push(...events);
        return Promise.resolve({ settled: events.length });
      },
    });

    expect(captured.map((e) => e.content)).toEqual(['a prompt that was not delivered']);
    expect(JSON.stringify(captured)).not.toContain(VARIABLE);
  });
});
