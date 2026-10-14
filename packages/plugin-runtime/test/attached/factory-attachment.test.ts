import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  readAttachedIdentity,
  recordValidatedWorkAccount,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type * as SchemaModule from '@akasecurity/schema';
import { agentKey, defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { resolveGatewayForConfig } from '../../src/attached/factory.ts';
import type * as GatewayModule from '../../src/attached/gateway.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

/**
 * What the factory hands the attached gateway as its `attachment`.
 *
 * Two seams, both file-scoped `vi.mock`s and so both hoisted:
 * - the gateway class is subclassed to record the deps it was built with;
 * - the scope resolver is wrapped to record what it was asked.
 *
 * The second pins the WIRING (the settings scope and the connection endpoint
 * reach the resolver), which a machine credential cannot show from the outside:
 * machine mode ignores both.
 */
const seen = vi.hoisted(() => ({
  attachments: [] as unknown[],
  resolveScopeInputs: [] as unknown[],
}));

vi.mock('@akasecurity/schema', async (importOriginal) => {
  const actual = await importOriginal<typeof SchemaModule>();
  return {
    ...actual,
    resolveScope: (...args: Parameters<typeof actual.resolveScope>) => {
      seen.resolveScopeInputs.push(args[0]);
      return actual.resolveScope(...args);
    },
  };
});

vi.mock('../../src/attached/gateway.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof GatewayModule>();
  class RecordingGateway extends actual.AttachedDataGateway {
    constructor(deps: GatewayModule.AttachedDataGatewayDeps) {
      super(deps);
      seen.attachments.push(deps.attachment);
    }
  }
  return { ...actual, AttachedDataGateway: RecordingGateway };
});

const ENDPOINT = 'https://plane.example.test';
const TEST_KEY = 'not-a-real-key';
const AT = '2026-09-30T12:00:00.000Z';
const SCOPE = {
  endpoint: ENDPOINT,
  entries: [{ kind: 'repo', identity: 'github.com/org/api', enrolledAt: AT }],
};

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-factory-attachment-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
  seen.attachments.length = 0;
  seen.resolveScopeInputs.length = 0;
});

afterEach(() => {
  removeTree(home);
});

function attachedSettings(): SchemaModule.WorkspaceSettings {
  return {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    attachmentScope: SCOPE,
  };
}

function configFor(settings: SchemaModule.WorkspaceSettings): PluginConfig {
  return {
    settings,
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

/** A machine credential. */
function writeMachineCredential(): void {
  writeControlPlaneCredential(settingsDirOf(home), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    mintedAt: AT,
  });
}

describe('the attachment the factory builds', () => {
  it('a machine credential resolves the machine mode, whatever scope the settings carry', async () => {
    writeMachineCredential();
    const gateway = resolveGatewayForConfig(configFor(attachedSettings()));
    try {
      expect(gateway).not.toBeInstanceOf(StandaloneDataGateway);
      expect(seen.attachments).toHaveLength(1);
      const attachment = seen.attachments[0] as SchemaModule.ResolvedAttachmentScope;
      expect(attachment.mode).toBe('machine');
      expect([...attachment.keys]).toEqual([]);
      // The wiring a scoped attachment is resolved through: the credential's
      // mode, the settings' scope and the connection's endpoint, all reaching
      // the resolver.
      expect(seen.resolveScopeInputs).toContainEqual({
        mode: 'machine',
        scope: SCOPE,
        endpoint: ENDPOINT,
      });
    } finally {
      await gateway.close();
    }
  });

  // Fail-closed toward the server: a fault while resolving what may be
  // forwarded leaves the machine on the local gateway, forwarding nothing.
  it('a throw while resolving the attachment falls back to the local gateway', async () => {
    writeMachineCredential();
    const settings = attachedSettings();
    Object.defineProperty(settings, 'attachmentScope', {
      get: () => {
        throw new Error('settings member unreadable');
      },
    });
    const gateway = resolveGatewayForConfig(configFor(settings));
    try {
      expect(gateway).toBeInstanceOf(StandaloneDataGateway);
      expect(seen.attachments).toEqual([]);
    } finally {
      await gateway.close();
    }
  });
});

describe('the attachment the factory builds — work accounts', () => {
  const WORK_KEY = 'github.com/org/api';
  const LEARNED = `claude:${randomUUID()}`;
  const MANUAL = `claude:${randomUUID()}`;
  const EMAIL = ['member', 'example.test'].join('@');

  const scopedCredential = (apiKey = TEST_KEY) =>
    ({ specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey, mintedAt: AT }) as const;

  // The identity record a scoped attach writes for the credential holding
  // `apiKey`, and one work account a hook validated under it.
  function learn(account: string, apiKey = TEST_KEY): void {
    writeAttachedIdentity(dataDirOf(home), {
      endpoint: ENDPOINT,
      apiKey,
      tenantName: 'Acme',
      userEmail: EMAIL,
    });
    recordValidatedWorkAccount(dataDirOf(home), {
      endpoint: ENDPOINT,
      credential: scopedCredential(apiKey),
      key: account,
    });
  }

  function agentKeyOf(account: string): string {
    const record = readAttachedIdentity(dataDirOf(home));
    if (record === undefined) throw new Error('no identity record was written');
    const key = agentKey(record.scopeTag, account);
    if (key === undefined) throw new Error('no agent key was built');
    return key;
  }

  async function keysFor(settings: SchemaModule.WorkspaceSettings): Promise<string[]> {
    const gateway = resolveGatewayForConfig(configFor(settings));
    try {
      expect(seen.attachments).toHaveLength(1);
      return [...(seen.attachments[0] as SchemaModule.ResolvedAttachmentScope).keys].sort();
    } finally {
      await gateway.close();
    }
  }

  it('adds the agent key of each work account the identity record learned', async () => {
    writeControlPlaneCredential(settingsDirOf(home), scopedCredential());
    learn(LEARNED);
    // The precondition, so the case cannot pass on a record that learned nothing.
    expect(readAttachedIdentity(dataDirOf(home))?.workAccounts.map((e) => e.identity)).toEqual([
      LEARNED,
    ]);

    expect(await keysFor(attachedSettings())).toEqual([WORK_KEY, agentKeyOf(LEARNED)].sort());
  });

  it('adds nothing from an identity record bound to another key', async () => {
    writeControlPlaneCredential(settingsDirOf(home), scopedCredential());
    learn(LEARNED, 'another-key-entirely');

    expect(await keysFor(attachedSettings())).toEqual([WORK_KEY]);
  });

  it('leaves a learned account out once work subscriptions are off, and keeps one enrolled by hand for coding sessions', async () => {
    writeControlPlaneCredential(settingsDirOf(home), scopedCredential());
    learn(LEARNED);
    const settings: SchemaModule.WorkspaceSettings = {
      ...attachedSettings(),
      attachmentScope: {
        ...SCOPE,
        workSubscriptions: 'off',
        entries: [
          ...SCOPE.entries,
          { kind: 'account', identity: MANUAL, enrolledAt: AT, codingAgents: true },
        ],
      },
    };

    // The manual entry's bare key is there for its claude.ai chats, and its
    // agent key for its coding sessions; the learned account is in neither form.
    expect(await keysFor(settings)).toEqual([WORK_KEY, MANUAL, agentKeyOf(MANUAL)].sort());
  });

  it('adds nothing on a machine credential, whatever the identity record learned', async () => {
    writeMachineCredential();
    learn(LEARNED);

    expect(await keysFor(attachedSettings())).toEqual([]);
  });
});
