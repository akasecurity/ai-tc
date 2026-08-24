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
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { dbPath as dbPathOf } from '@akasecurity/plugin-sdk';
import { ATTACHED_CREDENTIAL_FILENAME } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { takeBlockedAttempts } from '../../../../test/setup/no-network.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { configuredGatewayFactory, standaloneGatewayFactory } from '../../src/resolve.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';

// The switch that decides whether a machine forwards anything at all.
//
// The case that matters most here is the NEGATIVE one: a machine that has never
// attached must construct the same gateway it always did, and must not so much
// as look at a network. Everything else in attached mode is downstream of that
// staying true.

const ENDPOINT = 'https://aka.example-org.internal';
const ATTACHED_AT = '2026-08-24T10:00:00.000Z';
const KEY = 'not-a-real-key-2b7d4f9a1c63';

let home: string;

const configFor = (base: string): PluginConfig => ({
  settings: readWorkspaceSettings(base),
  dataDir: dataDirOf(base),
  dbPath: dbPathOf(base),
  settingsDir: settingsDirOf(base),
  onboarded: true,
  provider: { provider: 'anthropic' },
});

const attach = (base: string, endpoint = ENDPOINT): void => {
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-08-24T10:00:00.000Z' } },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint,
    apiKey: KEY,
  });
};

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-resolve-attached-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('a machine that has not attached', () => {
  it('gets the local gateway, exactly as before attached mode existed', () => {
    const gateway = configuredGatewayFactory(configFor(home));
    expect(gateway).toBeInstanceOf(StandaloneDataGateway);
  });

  it('attempts no network while resolving', () => {
    // The runtime guard records a refusal even when a caller swallows it, so
    // draining it is how this asserts on the absence rather than on a throw
    // nobody would have seen.
    configuredGatewayFactory(configFor(home));
    expect(takeBlockedAttempts()).toEqual([]);
  });
});

describe('a machine with only half an attachment', () => {
  it('stays local when settings name a plane but no credential is present', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-08-24T10:00:00.000Z' },
      },
      home,
    );
    expect(configuredGatewayFactory(configFor(home))).toBeInstanceOf(StandaloneDataGateway);
  });

  it('stays local when a credential is present but settings name no plane', () => {
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: 'not-a-real-key-2b7d4f9a1c63',
    });
    expect(configuredGatewayFactory(configFor(home))).toBeInstanceOf(StandaloneDataGateway);
  });

  it('stays local when the credential belongs to another deployment', () => {
    // The administrator-repoint case. Presenting the credential here would send
    // it to a host it was never minted for, so the machine falls back rather
    // than forwarding.
    attach(home);
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint: 'https://aka.somewhere-else.internal',
          attachedAt: '2026-08-24T12:00:00.000Z',
        },
      },
      home,
    );
    expect(configuredGatewayFactory(configFor(home))).toBeInstanceOf(StandaloneDataGateway);
  });

  it('stays local when the credential names an endpoint it would never send to', () => {
    // Written PAST the writer's own refusal, by hand — which is the only way
    // this state occurs, and exactly why the read side checks too rather than
    // trusting that every writer went through `writeControlPlaneCredential`.
    const plaintext = 'http://aka.example-org.internal';
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: plaintext, attachedAt: ATTACHED_AT } },
      home,
    );
    const dir = settingsDirOf(home);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, ATTACHED_CREDENTIAL_FILENAME),
      JSON.stringify({ specVersion: 1, endpoint: plaintext, apiKey: KEY }),
      { mode: 0o600 },
    );

    expect(configuredGatewayFactory(configFor(home))).toBeInstanceOf(StandaloneDataGateway);
  });
});

describe('a fully attached machine', () => {
  it('gets the forwarding decorator over the same local gateway', () => {
    attach(home);
    const gateway = configuredGatewayFactory(configFor(home));
    expect(gateway).toBeInstanceOf(AttachedDataGateway);
  });

  it('still opens no socket merely by being resolved', () => {
    // Constructing the decorator wires a client; it does not use one. A machine
    // that resolves a gateway and then does nothing must send nothing.
    attach(home);
    configuredGatewayFactory(configFor(home));
    expect(takeBlockedAttempts()).toEqual([]);
  });
});

describe('the explicit local factory', () => {
  it('ignores configuration entirely', () => {
    // A caller that wants the local gateway asks for it by name rather than by
    // arranging for a file to be absent.
    attach(home);
    expect(standaloneGatewayFactory(configFor(home))).toBeInstanceOf(StandaloneDataGateway);
  });
});
