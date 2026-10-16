import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  readWorkspaceSettings,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { AttachedCredentialAny, ManagedSettings } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION, SIGHTING_SHARE_PAYLOAD_NOTE } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { runDetach, runStatus } from '../../src/commands/attach.ts';
import { runScan } from '../../src/commands/scan.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { migratedStore } from '../helpers/store-templates.ts';

const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const MACHINE: AttachedCredentialAny = {
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey: 'placeholder',
  mintedAt: MINTED_AT,
};
const SCOPED: AttachedCredentialAny = { ...MACHINE, specVersion: 2, mode: 'scoped' };

const pinned = (value: boolean): ManagedSettings => ({
  specVersion: 1,
  organization: 'Acme',
  values: { sightingShareConsent: value },
  lockedFields: [],
});

let home: string;
let root: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-sighting-home-'));
  root = mkdtempSync(join(tmpdir(), 'aka-sighting-root-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([home, root]);
  process.exitCode = undefined;
});

function attach(credential: AttachedCredentialAny): void {
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT } },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDir(home), credential);
}

function grant(): void {
  applyOnboarding(
    {
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint: ENDPOINT,
      },
    },
    home,
    null,
  );
}

async function status(managedSettings: ManagedSettings | null = null): Promise<string> {
  const out: string[] = [];
  const io: Prompter = {
    out: (text) => out.push(text),
    err: () => undefined,
    isInteractive: false,
    ask: () => Promise.reject(new Error('unscripted prompt')),
    askHidden: () => Promise.reject(new Error('unscripted prompt')),
    readAllStdin: () => Promise.resolve(''),
  };
  await runStatus([], { base: home, prompter: io, managedSettings, exit: () => undefined });
  return out.join('');
}

async function scanText(managedSettings: ManagedSettings | null = null): Promise<string> {
  mkdirSync(dataDir(home), { recursive: true });
  migratedStore.seed(dataDir(home));
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  await runScan([root, '--home', home, '--no-forward'], { managedSettings });
  vi.restoreAllMocks();
  return out;
}

describe('aka status — credential sightings', () => {
  it('says a standalone machine shares nothing, and what would be sent', async () => {
    const out = await status();
    expect(out).toContain(
      'Credential sightings: off (standalone) — this machine is not attached to an organization.',
    );
    expect(out).toContain(SIGHTING_SHARE_PAYLOAD_NOTE);
  });

  it('says sharing is required on a machine-wide attachment the administrator pinned on', async () => {
    attach(MACHINE);
    expect(await status(pinned(true))).toContain(
      'Credential sightings: on (attached, machine-wide) — required by Acme on this managed machine.',
    );
  });

  it('says a scoped attachment shares only after the user opts in', async () => {
    attach(SCOPED);
    expect(await status(pinned(true))).toContain(
      'Credential sightings: off (attached, scoped) — you have not opted in.',
    );
    grant();
    expect(await status()).toContain('Credential sightings: on (attached, scoped) — you opted in.');
  });

  it('says a pinned false turns sharing off', async () => {
    attach(MACHINE);
    grant();
    expect(await status(pinned(false))).toContain(
      'Credential sightings: off (attached, machine-wide) — turned off by Acme.',
    );
  });
});

describe('aka scan — credential sightings footer', () => {
  it('ends with one line saying whether sightings are shared', async () => {
    const out = await scanText();
    const lines = out.trimEnd().split('\n');
    expect(lines.at(-1)).toBe(
      'Credential sightings: off (standalone) — this machine is not attached to an organization. ' +
        SIGHTING_SHARE_PAYLOAD_NOTE,
    );
  });

  it('says a sharing machine skipped sharing for a --no-forward run', async () => {
    attach(MACHINE);
    const out = await scanText(pinned(true));
    expect(out.trimEnd().split('\n').at(-1)).toBe(
      'Credential sightings: not shared — forwarding was skipped for this scan. ' +
        SIGHTING_SHARE_PAYLOAD_NOTE,
    );
  });

  it('adds nothing to the JSON payload', async () => {
    mkdirSync(dataDir(home), { recursive: true });
    migratedStore.seed(dataDir(home));
    let out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
    await runScan([root, '--home', home, '--format', 'json', '--no-forward'], {
      managedSettings: null,
    });
    vi.restoreAllMocks();
    expect(out).not.toContain('Credential sightings');
    expect(() => JSON.parse(out) as unknown).not.toThrow();
  });
});

describe('aka detach — credential sightings', () => {
  it('clears the grant with the attachment it named', () => {
    attach(SCOPED);
    grant();
    expect(readWorkspaceSettings(home).sightingShareConsent).toBeDefined();
    const exits: number[] = [];
    runDetach([], {
      base: home,
      prompter: {
        out: () => undefined,
        err: () => undefined,
        isInteractive: false,
        ask: () => Promise.reject(new Error('unscripted prompt')),
        askHidden: () => Promise.reject(new Error('unscripted prompt')),
        readAllStdin: () => Promise.resolve(''),
      },
      managedSettings: null,
      uninstallBackgroundSync: () => undefined,
      exit: (code) => exits.push(code),
    });
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(home).runMode).toBe('standalone');
    expect(readWorkspaceSettings(home).sightingShareConsent).toBeUndefined();
  });
});
