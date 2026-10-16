import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  createSightingKeyStore,
  keysDir,
  settingsDir,
  sightingKeyEndpointFingerprint,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { planSightingShare, sendScanSightings, sightingToken } from '../src/scan-sightings.ts';

// Nothing listens on port 1, so a request there is refused at once.
const CLOSED_ENDPOINT = 'http://localhost:1';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const KEY_BYTES = Buffer.alloc(32, 4);

let home: string;
let root: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-runtime-sightings-home-'));
  root = mkdtempSync(join(tmpdir(), 'aka-runtime-sightings-root-'));
});

afterEach(() => {
  removeTrees([home, root]);
});

function sharingMachine(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: CLOSED_ENDPOINT, attachedAt: MINTED_AT },
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint: CLOSED_ENDPOINT,
      },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDir(home), {
    specVersion: 1,
    endpoint: CLOSED_ENDPOINT,
    apiKey: ['test', 'plugin', 'key'].join('-'),
    mintedAt: MINTED_AT,
  });
  createSightingKeyStore('file', keysDir(home)).replace({
    keyVersion: 1,
    algorithm: 'hmac-sha256',
    key: KEY_BYTES.toString('base64url'),
    fetchedAtMs: Date.now(),
    endpointFingerprint: sightingKeyEndpointFingerprint(CLOSED_ENDPOINT),
  });
}

function input() {
  const plan = planSightingShare(home, { managedSettings: null });
  if (!plan.ok) throw new Error('expected a sharing plan');
  return {
    project: { projectKey: `path:${root}`, name: 'widgets', root },
    sightings: [
      {
        token: sightingToken(plan.key, ['value', 'for', 'test'].join('-')),
        ruleId: 'test/secret',
        file: join(root, 'a.ts'),
      },
    ],
  };
}

describe('sendScanSightings', () => {
  it('sends through the transport it is handed', async () => {
    sharingMachine();
    const send = vi.fn(() => Promise.resolve({ ok: true as const, accepted: 1 }));

    const outcome = await sendScanSightings(home, input(), { send, managedSettings: null });

    expect(outcome).toEqual({ status: 'sent', shared: 1, keptLocal: 0, unsent: 0 });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('sends through the attached transport by default, and reads a refusal as a failure', async () => {
    sharingMachine();

    const outcome = await sendScanSightings(home, input(), { managedSettings: null });

    expect(outcome).toEqual({
      status: 'sent',
      shared: 0,
      keptLocal: 0,
      unsent: 1,
      failure: 'unreachable',
    });
  });

  it('sends nothing from a machine that does not share', async () => {
    const send = vi.fn();

    const outcome = await sendScanSightings(
      home,
      { project: { projectKey: `path:${root}`, name: 'w', root }, sightings: [] },
      { send, managedSettings: null },
    );

    expect(outcome).toMatchObject({ status: 'not-shared', reason: 'sharing-off' });
    expect(send).not.toHaveBeenCalled();
  });
});
