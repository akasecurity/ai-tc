import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  applyOnboarding,
  readEffectiveSettings,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import {
  HISTORY_SYNC_PAYLOAD_VERSION,
  MANAGED_SETTINGS_FILENAME,
  ManagedSettingKey,
  ManagedSettings,
  ManagedSettingsValues,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The attach decides the order of its two writes from `readWorkspaceSettings()`,
// the settings in force with an administrator's overlay applied, and so does
// `aka attach` (`readEffectiveSettings(...).settings`): the same merge, over the
// same two fields. The write itself merges over the user's own file. The two
// views agree on the fields the order rule reads, `attachmentScope` and
// `historySyncConsent`, only because the overlay has no way to carry either. The
// claim lives in a comment at the call in the settings actions, and this file is
// its guard: if the overlay ever grows one of the two, a test here fails first.
const newHome = tempHomes('aka-attach-overlay-fields-');

const ENDPOINT = 'https://aka.example.com';
const PINNED_ENDPOINT = 'https://aka.example.net';
const ISO = '2026-10-01T00:00:00.000Z';
const THE_TWO = ['attachmentScope', 'historySyncConsent'] as const;

/** The user's own enrolled list and history grant, as an attach over a personal device leaves them. */
const LIST = {
  endpoint: ENDPOINT,
  tenantName: 'Example Org',
  userEmail: 'operator',
  entries: [{ kind: 'repo', identity: 'github.com/acme/payments-api', enrolledAt: ISO }],
};
const GRANT = {
  acknowledgedAt: ISO,
  payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
  endpoint: ENDPOINT,
};

let home: string;

beforeEach(() => {
  home = newHome();
});

afterEach(() => {
  // Back to the setup file's declaration: no administrator.
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
});

/** Place an administrator's file inside this home and make it the one this process reads. */
function administer(overlay: unknown): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

describe('what an administrator can pin or lock', () => {
  it('names neither the enrolled list nor the history grant', () => {
    for (const name of THE_TWO) {
      expect(ManagedSettingKey.options).not.toContain(name);
      expect(Object.keys(ManagedSettingsValues.shape)).not.toContain(name);
    }
  });

  it('reports an overlay that tries to pin or lock them as naming unknown fields, and applies neither', () => {
    // Stored by the user, with no administrator in the way.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
        attachmentScope: LIST,
        historySyncConsent: GRANT,
      },
      join(home, '.aka'),
      null,
    );
    const overlay = {
      specVersion: 1,
      organization: 'Example Org',
      values: {
        // A pin that is visible in the settings in force, so the overlay is not inert.
        controlPlane: { endpoint: PINNED_ENDPOINT },
        attachmentScope: { ...LIST, entries: [] },
        historySyncConsent: { ...GRANT, endpoint: PINNED_ENDPOINT },
      },
      lockedFields: [...THE_TWO],
    };
    administer(overlay);

    const parsed = ManagedSettings.parse(overlay);
    expect(parsed.unknownValueFields).toEqual([...THE_TWO]);
    expect(parsed.unknownLockedFields).toEqual([...THE_TWO]);
    expect(parsed.lockedFields).toEqual([]);
    expect(Object.keys(parsed.values)).toEqual(['controlPlane']);

    const inForce = readWorkspaceSettings(join(home, '.aka'));
    expect(inForce.controlPlane?.endpoint).toBe(PINNED_ENDPOINT);
    expect(inForce.attachmentScope).toEqual(LIST);
    expect(inForce.historySyncConsent).toEqual(GRANT);
  });

  it('hands the order rule the same settings the terminal command hands it', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
        attachmentScope: LIST,
        historySyncConsent: GRANT,
      },
      join(home, '.aka'),
      null,
    );
    const overlay = {
      specVersion: 1,
      organization: 'Example Org',
      values: { runMode: 'attached', controlPlane: { endpoint: PINNED_ENDPOINT } },
      lockedFields: ['runMode'],
    };
    administer(overlay);

    const dashboardsRead = readWorkspaceSettings(join(home, '.aka'));
    const terminalsRead = readEffectiveSettings(join(home, '.aka'), ManagedSettings.parse(overlay));

    // The overlay is in force in both, and they are one object's worth of settings.
    expect(dashboardsRead.controlPlane?.endpoint).toBe(PINNED_ENDPOINT);
    expect(dashboardsRead).toEqual(terminalsRead.settings);
  });
});
