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
import type {
  AttachmentMode,
  IngestBatch,
  IngestEvent,
  InventoryContext,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { defaultWorkspaceSettings, SOURCE_TOOL, StorePostureSnapshot } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { resolveGatewayForConfig } from '../../src/attached/factory.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// The hook forward path on a machine whose credential file really is a scoped
// (v2) one: the real reader, the real factory, the real attached gateway and a
// real local store. Only the network client is faked. The scope cases in the
// gateway suite build the attachment by hand; this file is what fails when a
// v2 file stops reaching the gateway as a scoped attachment. Refused by the
// reader, the factory builds the local gateway, which sends nothing. Read as a
// machine attachment, the gateway sends everything.
//
// The device report is judged here too, from both credential versions on the
// same settings: a scoped credential's report names its mode, and a machine
// credential's carries no mode at all. A scoped credential whose stored scope
// is missing, empty, another deployment's or unreadable still reports, with
// its mode, while a session's inventory stays local.

const sent = vi.hoisted(() => ({
  batches: [] as IngestBatch[],
  inventory: [] as InventoryContext[],
  posture: [] as StorePostureSnapshot[],
}));

// The real module is spread first: the forward policy classifies a failed send
// with the transport's own helpers, and a bare factory would leave them
// undefined. The client implements every member the attached gateway holds,
// typed as that client, so a member added to it later fails to compile here.
// A member left out would throw inside the forward breaker, and a case that
// asserts nothing was sent would then pass for the wrong reason.
vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: (): AttachedClient => ({
    ingestEvents: (batch) => {
      sent.batches.push(batch);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    },
    ingestInventory: (context) => {
      sent.inventory.push(context);
      return Promise.resolve({ hostId: 'tenant-host', sourceProjectId: 'tenant-project' });
    },
    recordAuditEvent: () => Promise.resolve(),
    recordAuditEvents: (events) => Promise.resolve({ accepted: events.length }),
    reportStorePosture: (snapshot) => {
      sent.posture.push(snapshot);
      return Promise.resolve({});
    },
    recordProjectEgress: () => Promise.resolve({}),
  }),
}));

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-09-01T10:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
/** The personal repository's origin, as a checkout of it records it. */
const PERSONAL_ORIGIN = `https://${PERSONAL_REPO}.git`;
/** The enrolled repository's origin, as a checkout of it records it. */
const WORK_ORIGIN = `https://${WORK_REPO}.git`;

/** What a machine attachment's report carries without a plugin block, in wire order. */
const MACHINE_REPORT_KEYS = [
  'deviceId',
  'hostname',
  'capturedAt',
  'storePresent',
  'schemaVersion',
  'findingsTotal',
  'findingsFirstAt',
  'findingsLastAt',
  'packs',
  'policyCounts',
];

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-factory-scoped-cred-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
  sent.batches.length = 0;
  sent.inventory.length = 0;
  sent.posture.length = 0;
});

afterEach(() => {
  removeTree(home);
});

/** The stored scope unless a case says otherwise: the work repository, on this endpoint. */
const ENROLLED: Pick<WorkspaceSettings, 'attachmentScope'> = {
  attachmentScope: {
    endpoint: ENDPOINT,
    entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
  },
};

/**
 * A credential of the given kind on disk, and settings that hold `scope`
 * (spread in whole, so `{}` stores no scope at all). By default the settings
 * are the same for both kinds, so only the credential file tells a scoped
 * attachment from a machine one.
 */
function attachedConfig(
  mode: AttachmentMode,
  scope: Pick<WorkspaceSettings, 'attachmentScope'> = ENROLLED,
): PluginConfig {
  writeControlPlaneCredential(
    settingsDirOf(home),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT },
  );
  const settings: WorkspaceSettings = {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    ...scope,
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

/** A scoped credential on disk, and settings that enroll one repository. */
const scopedConfig = (): PluginConfig => attachedConfig('scoped');

const prompt = (contentHash: string): IngestEvent => ({
  id: randomUUID(),
  sourceTool: 'claude-code',
  kind: 'prompt',
  occurredAt: '2026-09-01T11:00:00.000Z',
  contentHash,
  content: `content of ${contentHash}`,
});

/** The inventory the resolver builds for a coding session in a checkout whose origin is `url`. */
const sessionInventory = (url: string): InventoryContext => ({
  harness: {
    objectType: 'harness',
    identityKey: SOURCE_TOOL.ClaudeCode,
    title: SOURCE_TOOL.ClaudeCode,
    attributes: {},
  },
  // The scope verdict reads the project's url, never its name, so one name
  // serves every checkout.
  project: { url, name: 'checkout', attributes: {} },
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

describe('resolveGatewayForConfig — the device report names the attachment mode', () => {
  it('reports attachmentMode scoped, last, from a scoped credential in a personal session', async () => {
    const gateway = resolveGatewayForConfig(scopedConfig());
    try {
      await gateway.ensureInventory(sessionInventory(PERSONAL_ORIGIN));
    } finally {
      await gateway.close();
    }

    // The personal session's inventory stays on the machine. The report is the
    // device's liveness channel and goes out regardless.
    expect(sent.inventory).toEqual([]);
    expect(sent.posture).toHaveLength(1);
    const [report] = sent.posture;
    expect(report?.attachmentMode).toBe('scoped');
    expect(Object.keys(report ?? {})).toEqual([...MACHINE_REPORT_KEYS, 'attachmentMode']);
    expect(report?.storePresent).toBe(true);
    expect(StorePostureSnapshot.safeParse(report).success).toBe(true);
  });

  it('sends no attachmentMode from a machine credential on the same settings', async () => {
    const gateway = resolveGatewayForConfig(attachedConfig('machine'));
    try {
      await gateway.ensureInventory(sessionInventory(PERSONAL_ORIGIN));
    } finally {
      await gateway.close();
    }

    // Machine-wide: the same personal session's inventory is forwarded.
    expect(sent.inventory).toHaveLength(1);
    expect(sent.posture).toHaveLength(1);
    const [report] = sent.posture;
    expect(report).not.toHaveProperty('attachmentMode');
    expect(Object.keys(report ?? {})).toEqual(MACHINE_REPORT_KEYS);
  });

  it("forwards the enrolled repository's inventory while its scope is usable", async () => {
    // The control for the cases below: the same session, on the enrolled
    // scope, is sent. So when they send no inventory, the scope is why.
    const gateway = resolveGatewayForConfig(scopedConfig());
    try {
      await gateway.ensureInventory(sessionInventory(WORK_ORIGIN));
    } finally {
      await gateway.close();
    }

    expect(sent.inventory).toHaveLength(1);
    expect(sent.posture).toHaveLength(1);
  });

  // A scoped machine with no usable scope forwards no activity and no
  // inventory, but its device report is its liveness channel: it still goes
  // out, and still names the mode. No stored scope at all is where a fresh
  // scoped attach starts, before its first enroll.
  it.each<{ label: string; scope: Pick<WorkspaceSettings, 'attachmentScope'> }>([
    { label: 'no stored scope', scope: {} },
    { label: 'an empty scope', scope: { attachmentScope: { endpoint: ENDPOINT, entries: [] } } },
    {
      label: 'a scope enrolled with another deployment',
      scope: {
        attachmentScope: {
          endpoint: 'https://other.example',
          entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
        },
      },
    },
    { label: 'a scope that does not parse', scope: { attachmentScope: 'not a scope' } },
  ])(
    'still reports attachmentMode scoped, and sends no inventory, with $label',
    async ({ scope }) => {
      const gateway = resolveGatewayForConfig(attachedConfig('scoped', scope));
      try {
        await gateway.ensureInventory(sessionInventory(WORK_ORIGIN));
      } finally {
        await gateway.close();
      }

      expect(sent.inventory).toEqual([]);
      expect(sent.posture).toHaveLength(1);
      const [report] = sent.posture;
      expect(report?.attachmentMode).toBe('scoped');
      expect(Object.keys(report ?? {})).toEqual([...MACHINE_REPORT_KEYS, 'attachmentMode']);
    },
  );
});
