import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { AttachedCredentialAny, ManagedSettings } from '@akasecurity/schema';
import { SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import { writeControlPlaneCredential } from '../src/control-plane-credential.ts';
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../src/managed-settings.ts';
import { applyOnboarding, readWorkspaceSettings } from '../src/settings.ts';
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

function grant(endpoint: string = ENDPOINT): void {
  applyOnboarding(
    {
      sightingShareConsent: {
        acknowledgedAt: new Date().toISOString(),
        version: SIGHTING_SHARE_CONSENT_VERSION,
        endpoint,
      },
    },
    store.home,
    null,
  );
}

function detach(managed: ManagedSettings | null = null): void {
  applyOnboarding(
    {
      runMode: 'standalone',
      controlPlane: undefined,
      historySyncConsent: undefined,
      sightingShareConsent: undefined,
      attachmentScope: undefined,
    },
    store.home,
    managed,
  );
}

afterEach(() => {
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
});

function writeManaged(values: Record<string, unknown>): string {
  const path = join(store.home, 'managed-settings.json');
  writeFileSync(path, JSON.stringify({ specVersion: 1, values, lockedFields: [] }));
  return path;
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

  it('fails closed to standalone when the managed override throws', () => {
    attach(MACHINE);
    grant();
    const malformed = {
      specVersion: 1,
      values: null,
      lockedFields: null,
    } as unknown as ManagedSettings;
    expect(readSightingSharing(store.home, malformed)).toEqual({
      mode: 'standalone',
      managed: false,
      sharing: false,
      reason: 'standalone',
      optedIn: false,
      locked: false,
    });
  });
  it('does not count a grant given for another deployment', () => {
    attach(SCOPED);
    grant('https://other.example');
    expect(readSightingSharing(store.home, null)).toMatchObject({
      sharing: false,
      optedIn: false,
      reason: 'not-opted-in',
      endpoint: ENDPOINT,
    });
  });

  it('does not carry a grant for deployment A over to deployment B', () => {
    attach(SCOPED);
    grant();
    expect(readSightingSharing(store.home, null).sharing).toBe(true);
    const other = 'https://cp-b.example';
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: other, attachedAt: MINTED_AT } },
      store.home,
      null,
    );
    writeControlPlaneCredential(store.settingsDir, { ...SCOPED, endpoint: other });
    expect(readSightingSharing(store.home, null)).toMatchObject({
      mode: 'scoped',
      sharing: false,
      optedIn: false,
      endpoint: other,
    });
  });

  it('is cleared by a detach, and does not return on a re-attach to the same deployment', () => {
    attach(SCOPED);
    grant();
    detach();
    expect(readWorkspaceSettings(store.home).sightingShareConsent).toBeUndefined();
    attach(SCOPED);
    expect(readSightingSharing(store.home, null)).toMatchObject({
      sharing: false,
      optedIn: false,
    });
  });

  it('lets a detach clear a grant the administrator locked', () => {
    attach(SCOPED);
    grant();
    const locked: ManagedSettings = {
      specVersion: 1,
      values: { sightingShareConsent: true },
      lockedFields: ['sightingShareConsent'],
    };
    detach(locked);
    expect(readWorkspaceSettings(store.home).sightingShareConsent).toBeUndefined();
  });

  it('never shows an administrator pin as the user grant in the settings in force', () => {
    attach(MACHINE);
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([writeManaged({ sightingShareConsent: true })]);
    expect(readSightingSharing(store.home)).toMatchObject({ sharing: true, optedIn: false });
    expect(readWorkspaceSettings(store.home).sightingShareConsent).toBeUndefined();
  });

  it('runs unmanaged when the managed file on disk is malformed, so a pinned false does not hold', () => {
    attach(MACHINE);
    grant();
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([
      writeManaged({ sightingShareConsent: false, vaultInlineReveal: 'not-a-mode' }),
    ]);
    expect(readSightingSharing(store.home)).toMatchObject({
      sharing: true,
      locked: false,
      reason: 'opted-in',
    });
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([writeManaged({ sightingShareConsent: false })]);
    expect(readSightingSharing(store.home)).toMatchObject({
      sharing: false,
      reason: 'managed-denied',
    });
  });
});
