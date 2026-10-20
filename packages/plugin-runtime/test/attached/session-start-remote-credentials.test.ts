import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
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
  AuditEventInput,
  InventoryContext,
  StorePostureSnapshot,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { defaultWorkspaceSettings, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import type * as SyncTriggerModule from '../../src/attached/sync-trigger.ts';
import { handleSessionStart } from '../../src/handle-session-start.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// A session start in a checkout whose origin remote carries a token in its
// userinfo and another in its query, through the real resolver and the real
// gateway factory beside a real local store. Only the network client and the
// detached policy refresh are replaced, by recorders.

const sent = vi.hoisted(() => ({
  inventory: [] as InventoryContext[],
  audit: [] as AuditEventInput[],
  posture: [] as StorePostureSnapshot[],
}));

vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: (): AttachedClient => ({
    ingestEvents: (batch) => Promise.resolve({ accepted: batch.events.length, duplicates: 0 }),
    ingestInventory: (context) => {
      sent.inventory.push(context);
      return Promise.resolve({ sourceProjectId: 'deployment-project' });
    },
    recordAuditEvent: (body) => {
      sent.audit.push(body);
      return Promise.resolve();
    },
    recordAuditEvents: (bodies) => {
      sent.audit.push(...bodies);
      return Promise.resolve({ accepted: bodies.length });
    },
    reportStorePosture: (snapshot) => {
      sent.posture.push(snapshot);
      return Promise.resolve({});
    },
    recordProjectEgress: () => Promise.resolve({}),
  }),
}));

vi.mock('../../src/attached/sync-trigger.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof SyncTriggerModule>()),
  triggerPolicySync: () => undefined,
}));

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-10-01T09:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const TOKEN = 'Vq8Rk2LwTn5Hs3';
const QUERY = 'Pm4Zx9Cb7Jd1Fy';
// The `@` is built from its char code so the userinfo does not read as an email address.
const USERINFO = `build-bot:${TOKEN}${String.fromCharCode(64)}`;
const CLEAN_REMOTE = 'https://github.com/acme/payments-api.git';
const TOKEN_REMOTE = `https://${USERINFO}github.com/acme/payments-api.git`;
const TOKEN_AND_QUERY_REMOTE = `${TOKEN_REMOTE}?t=${QUERY}#readme`;
const REPO_KEY = 'github.com/acme/payments-api';

let tmp: string;
let home: string;
let userHome: string;
let checkout: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-session-start-remote-'));
  home = join(tmp, 'aka');
  userHome = join(tmp, 'user-home');
  checkout = join(tmp, 'payments-api');
  mkdirSync(userHome, { recursive: true });
  migratedStore.seed(dataDirOf(home));
  for (const route of Object.values(sent)) route.length = 0;
});

afterEach(() => {
  removeTree(tmp);
});

/** A checkout at `checkout` whose origin is `url`. No git runs. */
function gitRepo(url: string): void {
  mkdirSync(join(checkout, '.git'), { recursive: true });
  writeFileSync(
    join(checkout, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n`,
  );
}

/** Attached to ENDPOINT, machine-wide or scoped to the payments repository. */
function attach(mode: 'scoped' | 'machine'): PluginConfig {
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
    attachmentScope: {
      endpoint: ENDPOINT,
      entries: [{ kind: 'repo', identity: REPO_KEY, enrolledAt: AT }],
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

async function start(sessionId: string, config: PluginConfig): Promise<void> {
  await handleSessionStart(
    { sessionId, cwd: checkout, tool: SOURCE_TOOL.ClaudeCode, homeDir: userHome },
    config,
  );
}

/** The local store's project rows. */
function storedProjects() {
  const db = new DatabaseSync(dbPathOf(home));
  try {
    return db.prepare('SELECT url, name FROM source_project').all();
  } finally {
    db.close();
  }
}

function sessionRoot(sessionId: string): AuditEventInput | undefined {
  return sent.audit.find((body) => body.eventType === 'session' && body.id === sessionId);
}

describe('handleSessionStart in a checkout whose remote carries credentials', () => {
  it('sends the remote without its credentials, query or fragment on a machine attachment', async () => {
    gitRepo(TOKEN_AND_QUERY_REMOTE);
    await start('s-machine', attach('machine'));

    expect(sent.inventory.map((context) => context.project)).toEqual([
      { url: CLEAN_REMOTE, name: 'payments-api', attributes: {} },
    ]);
    expect(sessionRoot('s-machine')?.attributes).toMatchObject({
      project: 'payments-api',
      repo: 'acme/payments-api',
    });
    const wire = JSON.stringify(sent);
    expect(wire).toContain(REPO_KEY);
    expect(wire).not.toContain(TOKEN);
    expect(wire).not.toContain(QUERY);
    // The local project row keeps the remote as the git config writes it.
    expect(storedProjects()).toEqual([{ url: TOKEN_AND_QUERY_REMOTE, name: 'payments-api' }]);
  });

  it('sends an enrolled repository whose remote carries a token, without it, on a scoped attachment', async () => {
    gitRepo(TOKEN_REMOTE);
    await start('s-scoped', attach('scoped'));

    expect(sent.inventory.map((context) => context.project?.url)).toEqual([CLEAN_REMOTE]);
    expect(sessionRoot('s-scoped')).toBeDefined();
    const wire = JSON.stringify(sent);
    expect(wire).toContain(REPO_KEY);
    expect(wire).not.toContain(TOKEN);
  });

  it('keeps a session local on a scoped attachment when its remote carries a query', async () => {
    gitRepo(TOKEN_AND_QUERY_REMOTE);
    await start('s-query', attach('scoped'));

    // A remote with a query gives no repository key, so neither the inventory
    // nor the root is in scope; posture is sent either way.
    expect(sent.inventory).toEqual([]);
    expect(sent.audit).toEqual([]);
    expect(sent.posture).toHaveLength(1);
  });

  it('sends a remote with nothing to remove as the git config writes it', async () => {
    gitRepo(CLEAN_REMOTE);
    await start('s-clean', attach('machine'));

    expect(sent.inventory.map((context) => context.project)).toEqual([
      { url: CLEAN_REMOTE, name: 'payments-api', attributes: {} },
    ]);
    expect(storedProjects()).toEqual([{ url: CLEAN_REMOTE, name: 'payments-api' }]);
  });
});
