import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type * as RemoteModule from '@akasecurity/remote';
import type { IngestBatch, IngestEvent, WorkspaceSettings } from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { resolveGatewayForConfig } from '../../src/attached/factory.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// The hook forward path on a machine whose credential file really is a scoped
// (v2) one: the real reader, the real factory, the real attached gateway and a
// real local store. Only the network client is faked. The scope cases in the
// gateway suite build the attachment by hand; this file is what fails when a
// v2 file stops reaching the gateway as a scoped attachment. Refused by the
// reader, the factory builds the local gateway, which sends nothing. Read as a
// machine attachment, the gateway sends everything.

const sent = vi.hoisted(() => ({ batches: [] as IngestBatch[] }));

// The real module is spread first: the forward policy classifies a failed send
// with the transport's own helpers, and a bare factory would leave them
// undefined.
vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: () => ({
    ingestEvents: (batch: IngestBatch) => {
      sent.batches.push(batch);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    },
  }),
}));

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-09-01T10:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-factory-scoped-cred-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
  sent.batches.length = 0;
});

afterEach(() => {
  removeTree(home);
});

/** A scoped credential on disk, and settings that enroll one repository. */
function scopedConfig(): PluginConfig {
  writeControlPlaneCredential(settingsDirOf(home), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    mintedAt: AT,
  });
  const settings: WorkspaceSettings = {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    attachmentScope: {
      endpoint: ENDPOINT,
      entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
    },
  };
  return {
    settings,
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

const prompt = (contentHash: string): IngestEvent => ({
  id: randomUUID(),
  sourceTool: 'claude-code',
  kind: 'prompt',
  occurredAt: '2026-09-01T11:00:00.000Z',
  contentHash,
  content: `content of ${contentHash}`,
});

describe('resolveGatewayForConfig — a scoped credential read from disk', () => {
  it('builds the attached gateway, not the local one', async () => {
    const gateway = resolveGatewayForConfig(scopedConfig());
    try {
      expect(gateway).not.toBeInstanceOf(StandaloneDataGateway);
    } finally {
      await gateway.close();
    }
  });

  it('sends an enrolled capture, and keeps a personal one local and never owed', async () => {
    const gateway = resolveGatewayForConfig(scopedConfig());
    try {
      // The personal capture goes first, so a gateway that forwarded it would
      // show it at the head of what was sent.
      await gateway.recordCapture({
        event: prompt('hash-personal'),
        findings: [],
        scopeKey: PERSONAL_REPO,
      });
      await gateway.recordCapture({
        event: prompt('hash-work'),
        findings: [],
        scopeKey: WORK_REPO,
      });
    } finally {
      await gateway.close();
    }

    expect(sent.batches.map((batch) => batch.events.map((e) => e.contentHash))).toEqual([
      ['hash-work'],
    ]);

    // Read straight off the table: both rows are written locally, and only the
    // delivery columns tell them apart.
    const raw = new DatabaseSync(dbPathOf(home));
    try {
      const rows = raw
        .prepare(
          `SELECT content_hash, outbox_owed, synced_at FROM audit_events
            WHERE event_type = 'prompt' ORDER BY content_hash`,
        )
        .all();
      expect(rows).toEqual([
        // Never forwarded, so never owed: the drain will not offer it either.
        { content_hash: 'hash-personal', outbox_owed: null, synced_at: null },
        // Delivered, so stamped synced rather than owed.
        { content_hash: 'hash-work', outbox_owed: null, synced_at: expect.any(Number) as number },
      ]);
    } finally {
      raw.close();
    }
  });
});
