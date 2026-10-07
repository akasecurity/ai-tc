import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ManagedSettings } from '@akasecurity/schema';
import { MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import { writeControlPlaneCredential } from '../src/control-plane-credential.ts';
import { managedConnectionHold, managedScopedRefusal } from '../src/managed-connection.ts';
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../src/managed-settings.ts';
import { applyOnboarding } from '../src/settings.ts';
import { useTempStore } from './helpers/temp-store.ts';

// A machine whose administrator governs the connection attaches machine-wide
// only. Governed means exactly what every other connection decision in this
// package reads: `runMode` locked, or `runMode` or `controlPlane` pinned. A
// scoped attach there would narrow a device the organization manages to the
// repositories its user enrolls.
//
// Every case states its administrator. The overlay is an argument wherever the
// subject is the decision; the one case whose subject is the DEFAULT read points
// the process-wide seam at a file inside this test's own home.

const store = useTempStore('aka-managed-scoped-');

const PINNED = 'https://pinned.example.test';
const ATTACHED_AT = '2026-10-01T00:00:00.000Z';
const ORG = 'Example Org';
const REFUSED = { reason: 'scoped-managed', organization: ORG } as const;

/** The fleet overlay's shape: the deployment pinned, the mode left alone. */
const planeOnly: ManagedSettings = {
  specVersion: 1,
  organization: ORG,
  values: { controlPlane: { endpoint: PINNED, label: 'example-prod' } },
  lockedFields: [],
};

const modeOnly: ManagedSettings = {
  specVersion: 1,
  organization: ORG,
  values: { runMode: 'attached' },
  lockedFields: [],
};

const lockOnly: ManagedSettings = {
  specVersion: 1,
  organization: ORG,
  values: {},
  lockedFields: ['runMode'],
};

const heldStandalone: ManagedSettings = {
  specVersion: 1,
  organization: ORG,
  values: { runMode: 'standalone' },
  lockedFields: [],
};

/** An administrator who governs other settings and leaves the connection alone. */
const otherSettingsOnly: ManagedSettings = {
  specVersion: 1,
  organization: ORG,
  values: { historicalAccess: 'full' },
  lockedFields: ['historicalAccess', 'vaultConsent'],
};

describe('managedScopedRefusal', () => {
  it('refuses nothing on an unmanaged machine', () => {
    expect(managedScopedRefusal(store.home, null)).toBeNull();
  });

  it('refuses nothing where the administrator governs other settings but not the connection', () => {
    expect(managedScopedRefusal(store.home, otherSettingsOnly)).toBeNull();
  });

  it.each<[string, ManagedSettings]>([
    ['the deployment pinned alone, as a fleet overlay ships it', planeOnly],
    ['the mode pinned alone', modeOnly],
    ['the mode locked', lockOnly],
    ['the mode held standalone', heldStandalone],
  ])('refuses a scoped attach under %s, naming the administrator', (_how, overlay) => {
    expect(managedScopedRefusal(store.home, overlay)).toEqual(REFUSED);
  });

  it('refuses where no detach refusal holds the machine: the pin on the deployment alone', () => {
    // The scoped refusal is wider than the mode hold on purpose. A pinned
    // deployment leaves `runMode` the user's, so neither attach nor detach is
    // held, and yet a scoped attach would still narrow a managed device.
    expect(managedConnectionHold(store.home, planeOnly)).toBeNull();
    expect(managedScopedRefusal(store.home, planeOnly)).toEqual(REFUSED);
  });

  it('carries no organization when the file names none', () => {
    const anonymous: ManagedSettings = {
      specVersion: 1,
      values: planeOnly.values,
      lockedFields: [],
    };
    const refusal = managedScopedRefusal(store.home, anonymous);
    expect(refusal).toEqual({ reason: 'scoped-managed' });
    expect(refusal).not.toHaveProperty('organization');
  });

  it('refuses on a device that became managed after a scoped attach', () => {
    // Attached scoped while unmanaged; the overlay arrived afterwards. The next
    // attach meets the refusal, because the decision reads the overlay alone.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: PINNED, attachedAt: ATTACHED_AT },
        attachmentScope: { endpoint: PINNED, entries: [] },
      },
      store.home,
      null,
    );
    writeControlPlaneCredential(store.settingsDir, {
      specVersion: 2,
      mode: 'scoped',
      endpoint: PINNED,
      apiKey: 'placeholder',
      mintedAt: ATTACHED_AT,
    });

    expect(managedScopedRefusal(store.home, null)).toBeNull();
    expect(managedScopedRefusal(store.home, planeOnly)).toEqual(REFUSED);
  });
});

describe('managedScopedRefusal — the default overlay', () => {
  afterEach(() => {
    // Back to the setup file's declaration: no administrator.
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
  });

  function installOverlay(contents: unknown): void {
    const dir = join(store.home, 'administrator');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, MANAGED_SETTINGS_FILENAME);
    writeFileSync(file, JSON.stringify(contents));
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
  }

  it('is the overlay this process reads when a caller passes none', () => {
    installOverlay(planeOnly);
    expect(managedScopedRefusal(store.home)).toEqual(REFUSED);
  });

  it('fails open to UNMANAGED on a damaged file, like every connection decision', () => {
    installOverlay({ values: { runMode: 'attachd' } });
    expect(managedScopedRefusal(store.home)).toBeNull();
  });
});
