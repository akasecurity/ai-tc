import type { AttachedCredentialAny, ManagedSettings } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { writeControlPlaneCredential } from '../src/control-plane-credential.ts';
import { applyOnboarding } from '../src/settings.ts';
import { readSightingSharing } from '../src/sighting-sharing.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-sighting-');

const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const KEY = 'placeholder';

const MACHINE: AttachedCredentialAny = {
  specVersion: 1,
  endpoint: ENDPOINT,
  apiKey: KEY,
  mintedAt: MINTED_AT,
};
const SCOPED: AttachedCredentialAny = { ...MACHINE, specVersion: 2, mode: 'scoped' };

function attach(credential: AttachedCredentialAny): void {
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT } },
    store.home,
    null,
  );
  writeControlPlaneCredential(store.settingsDir, credential);
}

function grant(): void {
  applyOnboarding(
    {
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
      },
    },
    store.home,
    null,
  );
}

const pinned = (value: boolean): ManagedSettings => ({
  specVersion: 1,
  values: { sightingShareConsent: value },
  lockedFields: [],
});

describe('readSightingSharing', () => {
  it('is standalone with no settings and no credential', () => {
    expect(readSightingSharing(store.home, null)).toMatchObject({
      mode: 'standalone',
      sharing: false,
      reason: 'standalone',
    });
  });

  it('is standalone when settings name a deployment but no credential is held', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT } },
      store.home,
      null,
    );
    grant();
    expect(readSightingSharing(store.home, null)).toMatchObject({
      mode: 'standalone',
      sharing: false,
    });
  });

  it('reads the mode from the credential file', () => {
    attach(MACHINE);
    expect(readSightingSharing(store.home, null).mode).toBe('machine');
    writeControlPlaneCredential(store.settingsDir, SCOPED);
    expect(readSightingSharing(store.home, null).mode).toBe('scoped');
  });

  it('shares on a machine-wide attachment when the managed file pins it on', () => {
    attach(MACHINE);
    expect(readSightingSharing(store.home, pinned(true))).toMatchObject({
      sharing: true,
      managed: true,
      locked: true,
      reason: 'managed-required',
    });
  });

  it('does not count the pin as an opt-in on a scoped attachment', () => {
    attach(SCOPED);
    expect(readSightingSharing(store.home, pinned(true))).toMatchObject({
      sharing: false,
      reason: 'not-opted-in',
    });
    grant();
    expect(readSightingSharing(store.home, pinned(true))).toMatchObject({
      sharing: true,
      reason: 'opted-in',
    });
  });

  it('never shares under a pinned false, whatever the user granted', () => {
    attach(MACHINE);
    grant();
    expect(readSightingSharing(store.home, pinned(false))).toMatchObject({
      sharing: false,
      locked: true,
      reason: 'managed-denied',
    });
  });

  it('shares on the user grant with no administrator', () => {
    attach(SCOPED);
    grant();
    expect(readSightingSharing(store.home, null)).toMatchObject({
      sharing: true,
      reason: 'opted-in',
      locked: false,
    });
  });
});
