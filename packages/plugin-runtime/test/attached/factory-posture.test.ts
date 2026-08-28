import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { dbPath as dbPathOf, resolveInventoryContext } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, StorePostureSnapshot } from '@akasecurity/schema';
import {
  SOURCE_TOOL,
  StorePostureSnapshot as StorePostureSnapshotSchema,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveGatewayForConfig } from '../../src/attached/factory.ts';
import { createPolicyStore } from '../../src/attached/policy-store.ts';

// What the posture channel actually SENDS once a machine is attached — the
// factory's own wiring, driven through the real gateway, the real posture
// store and the real on-disk policy cache, with only the socket-owning client
// replaced. The plugin block is the part with no other end-to-end pin: its
// identity half arrives from the resolving caller and its policy half from the
// cache the sync child writes, and only this seam sees the two composed.

const reported: StorePostureSnapshot[] = [];

vi.mock('@akasecurity/remote', () => ({
  createRemoteClient: () => ({
    ingestEvents: () => Promise.resolve({ accepted: 1, duplicates: 0 }),
    ingestInventory: () => Promise.resolve({}),
    recordAuditEvent: () => Promise.resolve(),
    reportStorePosture: (snapshot: StorePostureSnapshot) => {
      reported.push(snapshot);
      return Promise.resolve({ ok: true });
    },
  }),
}));

const ENDPOINT = 'https://aka.example-org.internal';
const BUILD = { package: '@akasecurity/ai-tc-claude-code', version: '0.9.8' };

const bundle = (version: string): PolicyBundle => ({
  version,
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-19T00:00:00.000Z',
});

let home: string;
let cwd: string;
const opened: DataGateway[] = [];

const configFor = (base: string): PluginConfig => ({
  settings: readWorkspaceSettings(base),
  dataDir: dataDirOf(base),
  dbPath: dbPathOf(base),
  settingsDir: settingsDirOf(base),
  onboarded: true,
  provider: { provider: 'anthropic' },
});

const attach = (base: string): void => {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-24T10:00:00.000Z' },
    },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: 'not-a-real-key-2b7d4f9a1c63',
  });
};

// One inventory pass through the resolved gateway — the call the posture
// report rides behind (see AttachedDataGateway.ensureInventory).
async function runInventoryPass(gateway: DataGateway): Promise<void> {
  await gateway.ensureInventory(
    resolveInventoryContext({ cwd, tool: SOURCE_TOOL.ClaudeCode, harnessVersion: '0.9.8' }),
  );
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-factory-posture-'));
  cwd = mkdtempSync(join(tmpdir(), 'aka-factory-posture-cwd-'));
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(
    join(cwd, '.git', 'config'),
    '[remote "origin"]\n\turl = git@github.com:org/payments-api.git\n',
  );
  reported.length = 0;
});

afterEach(async () => {
  await Promise.all(opened.map((gateway) => gateway.close().catch(() => undefined)));
  opened.length = 0;
  rmSync(home, { recursive: true, force: true });
  rmSync(cwd, { recursive: true, force: true });
});

describe('the attached factory wires the posture plugin block', () => {
  it('a build identity plus a cached bundle report as a full plugin block', async () => {
    attach(home);
    await createPolicyStore(dataDirOf(home)).write(bundle('sha256:abc123'));
    const gateway = resolveGatewayForConfig(configFor(home), { pluginBuild: BUILD });
    opened.push(gateway);
    await runInventoryPass(gateway);

    expect(reported).toHaveLength(1);
    const snapshot = reported[0];
    if (!snapshot) throw new Error('expected a posture report');
    expect(() => StorePostureSnapshotSchema.parse(snapshot)).not.toThrow();
    expect(snapshot.plugin).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      policyBundleVersion: 'sha256:abc123',
    });
    expect(snapshot.plugin?.policyFetchedAt).toBeGreaterThan(0);
  });

  it('a build identity with a cold policy cache still reports package and version', async () => {
    // The first report after `aka attach`: the sync child has not written the
    // cache yet, and identity must not wait for it — nulls say "no bundle
    // cached", not "unknown build".
    attach(home);
    const gateway = resolveGatewayForConfig(configFor(home), { pluginBuild: BUILD });
    opened.push(gateway);
    await runInventoryPass(gateway);

    expect(reported).toHaveLength(1);
    expect(reported[0]?.plugin).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      policyBundleVersion: null,
      policyFetchedAt: null,
    });
  });

  it('a caller with no build identity reports posture without a plugin block', async () => {
    attach(home);
    const gateway = resolveGatewayForConfig(configFor(home));
    opened.push(gateway);
    await runInventoryPass(gateway);

    expect(reported).toHaveLength(1);
    expect(reported[0]).not.toHaveProperty('plugin');
  });
});
