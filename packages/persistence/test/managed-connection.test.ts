import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ManagedSettings } from '@akasecurity/schema';
import { MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import { afterEach, describe, expect, it } from 'vitest';

import {
  managedAttachRefusal,
  managedConnectionHold,
  managedDetachRefusal,
} from '../src/managed-connection.ts';
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../src/managed-settings.ts';
import { applyOnboarding, readWorkspaceSettings } from '../src/settings.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The decision both connection surfaces make before they send or write anything:
// `aka attach` / `aka detach`, and the dashboard's attach and detach actions.
//
// Every case states its administrator. The overlay is passed as an argument
// wherever the subject is the decision, and the one case whose subject is the
// DEFAULT read points the process-wide seam at a file inside this test's own
// home — never at the machine's real managed file, which a developer laptop
// can carry.

const store = useTempStore('aka-managed-connection-');

const PINNED = 'https://pinned.example-org.internal';
const OTHER = 'https://other.example-org.internal';
const OWN = 'https://own.example-org.internal';
const ATTACHED_AT = '2026-08-01T00:00:00.000Z';

const fleet: ManagedSettings = {
  specVersion: 1,
  organization: 'Example Org',
  values: { runMode: 'attached', controlPlane: { endpoint: PINNED, label: 'example-prod' } },
  lockedFields: [],
};

const lockOnly: ManagedSettings = {
  specVersion: 1,
  organization: 'Example Org',
  values: {},
  lockedFields: ['runMode'],
};

const planeOnly: ManagedSettings = {
  specVersion: 1,
  organization: 'Example Org',
  values: { controlPlane: { endpoint: PINNED, label: 'example-prod' } },
  lockedFields: [],
};

const heldStandalone: ManagedSettings = {
  specVersion: 1,
  organization: 'Example Org',
  values: { runMode: 'standalone', controlPlane: { endpoint: PINNED } },
  lockedFields: [],
};

const modeOnly: ManagedSettings = {
  specVersion: 1,
  organization: 'Example Org',
  values: { runMode: 'attached' },
  lockedFields: [],
};

/** The user's own file, attached to `endpoint`, written with no administrator. */
function attachOwnFile(endpoint: string, label?: string): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint,
        attachedAt: ATTACHED_AT,
        ...(label === undefined ? {} : { label }),
      },
    },
    store.home,
    null,
  );
}

describe('managedAttachRefusal', () => {
  it('refuses nothing on an unmanaged machine, including a move to another deployment', () => {
    attachOwnFile(OWN);
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home, null)).toBeNull();
  });

  it('lets a machine attach to the endpoint a fleet overlay pinned — the enrolment path', () => {
    expect(managedAttachRefusal({ endpoint: PINNED }, store.home, fleet)).toBeNull();
    expect(
      managedAttachRefusal({ endpoint: PINNED, label: 'example-prod' }, store.home, fleet),
    ).toBeNull();
  });

  it('refuses an attach elsewhere under a pin with no lock, naming who pinned it and where', () => {
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home, fleet)).toEqual({
      reason: 'pinned-endpoint',
      organization: 'Example Org',
      endpoint: PINNED,
    });
  });

  it('refuses a label that differs from the pinned one, and only one that differs', () => {
    expect(
      managedAttachRefusal({ endpoint: PINNED, label: 'renamed-here' }, store.home, fleet),
    ).toEqual({ reason: 'pinned-label', organization: 'Example Org' });
    expect(
      managedAttachRefusal({ endpoint: PINNED, label: undefined }, store.home, fleet),
    ).toBeNull();
  });

  it.each<[string, ManagedSettings]>([
    ['pinned', heldStandalone],
    ['locked', lockOnly],
  ])('refuses any attach on a machine whose mode is %s to standalone', (_how, overlay) => {
    expect(managedAttachRefusal({ endpoint: PINNED }, store.home, overlay)).toEqual({
      reason: 'held-standalone',
      organization: 'Example Org',
    });
  });

  it('under a lock with no pin, holds the deployment the user last chose', () => {
    attachOwnFile(OWN);
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home, lockOnly)).toEqual({
      reason: 'pinned-endpoint',
      organization: 'Example Org',
      endpoint: OWN,
    });
    expect(managedAttachRefusal({ endpoint: OWN }, store.home, lockOnly)).toBeNull();
  });

  it('under a pin on the descriptor alone, still decides the endpoint', () => {
    expect(managedAttachRefusal({ endpoint: PINNED }, store.home, planeOnly)).toBeNull();
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home, planeOnly)).toMatchObject({
      reason: 'pinned-endpoint',
      endpoint: PINNED,
    });
  });

  it('under a pinned mode with no deployment named, leaves the endpoint to the user', () => {
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home, modeOnly)).toBeNull();
  });

  it('carries no organization when the file names none', () => {
    const anonymous: ManagedSettings = {
      specVersion: 1,
      values: fleet.values,
      lockedFields: [],
    };
    const refusal = managedAttachRefusal({ endpoint: OTHER }, store.home, anonymous);
    expect(refusal).toEqual({ reason: 'pinned-endpoint', endpoint: PINNED });
    expect(refusal).not.toHaveProperty('organization');
  });
});

describe('managedAttachRefusal — the name a governed connection keeps', () => {
  // Under a lock the writer refuses any change to the descriptor, measured
  // against the name every read shows. Under a pin with no lock, only a name the
  // administrator gave is one the next read would put back.

  it('under a lock, refuses renaming a deployment the user named', () => {
    attachOwnFile(OWN, 'Old');
    expect(managedAttachRefusal({ endpoint: OWN, label: 'New' }, store.home, lockOnly)).toEqual({
      reason: 'pinned-label',
      organization: 'Example Org',
    });
  });

  it('under a lock, refuses an attach that leaves the name off, since that drops it', () => {
    attachOwnFile(OWN, 'Old');
    expect(managedAttachRefusal({ endpoint: OWN }, store.home, lockOnly)).toEqual({
      reason: 'label-required',
      organization: 'Example Org',
    });
  });

  it('under a lock, lets an attach through that keeps the name it has', () => {
    attachOwnFile(OWN, 'Old');
    expect(managedAttachRefusal({ endpoint: OWN, label: 'Old' }, store.home, lockOnly)).toBeNull();
  });

  it('under a lock beside a pin that names no label, freezes the name the user gave', () => {
    attachOwnFile(PINNED, 'Old');
    const lockedPin: ManagedSettings = {
      ...lockOnly,
      values: { controlPlane: { endpoint: PINNED } },
    };
    expect(managedAttachRefusal({ endpoint: PINNED }, store.home, lockedPin)).toEqual({
      reason: 'label-required',
      organization: 'Example Org',
    });
  });

  it('under a pin that names no label, leaves renaming the user’s own name to the user', () => {
    attachOwnFile(PINNED, 'MyBox');
    const unnamed: ManagedSettings = {
      specVersion: 1,
      organization: 'Example Org',
      values: { controlPlane: { endpoint: PINNED } },
      lockedFields: [],
    };
    expect(
      managedAttachRefusal({ endpoint: PINNED, label: 'Renamed' }, store.home, unnamed),
    ).toBeNull();
  });
});

describe('managedDetachRefusal', () => {
  it('refuses nothing on an unmanaged machine', () => {
    attachOwnFile(OWN);
    expect(managedDetachRefusal(store.home, null)).toBeNull();
  });

  it('refuses under a fleet pin, even with nothing in the user file — the pin is what it reads', () => {
    expect(readWorkspaceSettings(store.home).runMode).toBe('standalone');
    expect(managedDetachRefusal(store.home, fleet)).toEqual({
      reason: 'held-attached',
      organization: 'Example Org',
      endpoint: PINNED,
    });
  });

  it('refuses under a lock while attached, naming the deployment it holds', () => {
    attachOwnFile(OWN);
    expect(managedDetachRefusal(store.home, lockOnly)).toEqual({
      reason: 'held-attached',
      organization: 'Example Org',
      endpoint: OWN,
    });
  });

  it('lets a locked machine that is not attached through, since there is nothing to undo', () => {
    expect(managedDetachRefusal(store.home, lockOnly)).toBeNull();
  });

  it('leaves a detach the user’s under a pin on the descriptor alone', () => {
    attachOwnFile(PINNED);
    expect(managedDetachRefusal(store.home, planeOnly)).toBeNull();
  });

  it('lets a detach through where the overlay holds the machine standalone', () => {
    expect(managedDetachRefusal(store.home, heldStandalone)).toBeNull();
  });

  it('lets a detach through under a pinned mode with no deployment named anywhere', () => {
    expect(managedDetachRefusal(store.home, modeOnly)).toBeNull();
  });
});

describe('managedConnectionHold', () => {
  // What a surface may offer at all: the refusal an attach or a detach from the
  // machine's current state would meet whatever is typed, or null.
  it('is the detach refusal on a machine held attached', () => {
    expect(managedConnectionHold(store.home, fleet)).toEqual(
      managedDetachRefusal(store.home, fleet),
    );
    expect(managedConnectionHold(store.home, fleet)?.reason).toBe('held-attached');
  });

  it('is the standalone refusal on a machine held standalone', () => {
    expect(managedConnectionHold(store.home, heldStandalone)).toEqual({
      reason: 'held-standalone',
      organization: 'Example Org',
    });
  });

  it.each<[string, ManagedSettings | null]>([
    ['an unmanaged machine', null],
    ['a pin on the descriptor alone', planeOnly],
    ['a pinned mode with no deployment named', modeOnly],
  ])('is null for %s, where what may be typed still decides', (_what, overlay) => {
    expect(managedConnectionHold(store.home, overlay)).toBeNull();
  });
});

describe('the default overlay', () => {
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

  it('is the one this process reads when a caller passes none', () => {
    installOverlay(fleet);
    expect(managedDetachRefusal(store.home)).toMatchObject({ reason: 'held-attached' });
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home)).toMatchObject({
      reason: 'pinned-endpoint',
    });
  });

  it('fails open to UNMANAGED on a damaged file rather than refusing everything', () => {
    installOverlay({ values: { runMode: 'attachd' } });
    expect(managedDetachRefusal(store.home)).toBeNull();
    expect(managedAttachRefusal({ endpoint: OTHER }, store.home)).toBeNull();
  });
});
