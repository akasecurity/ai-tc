import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type * as SchemaModule from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
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
