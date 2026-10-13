import { existsSync, readFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { SightingSharing } from '@akasecurity/schema';
import { isSightingShareConsentValid, SIGHTING_SHARE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { setSightingShareConsent } from '../../app/(app)/settings/actions.ts';
import { managedRefusal } from '../../app/lib/action-refusals.ts';
import { tempHomes } from '../helpers/temp-home.ts';

const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Stands in for a managed settings file, which lives at an absolute system path
// a temp home cannot redirect. Unarmed, the real reader runs.
const sharingState = vi.hoisted<{ value: SightingSharing | undefined }>(() => ({
  value: undefined,
}));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readSightingSharing: (...args: Parameters<typeof actual.readSightingSharing>) =>
      sharingState.value ?? actual.readSightingSharing(...args),
  };
});

const newHome = tempHomes('aka-web-sighting-');

beforeEach(() => {
  osHome.dir = newHome();
});

afterEach(() => {
  sharingState.value = undefined;
});

function settingsFile(): string {
  return join(osHome.dir, '.aka', 'settings', 'settings.json');
}

describe('setSightingShareConsent', () => {
  it('records a server-stamped grant', async () => {
    const before = Date.now();
    expect(await setSightingShareConsent({ choice: 'granted' })).toEqual({ ok: true });
    const consent = readWorkspaceSettings().sightingShareConsent;
    expect(consent?.version).toBe(SIGHTING_SHARE_CONSENT_VERSION);
    expect(isSightingShareConsentValid(consent)).toBe(true);
    expect(Date.parse(consent?.acknowledgedAt ?? '')).toBeGreaterThanOrEqual(before - 5_000);
  });

  it('keeps an existing grant and its acknowledgedAt on a repeated grant', async () => {
    await setSightingShareConsent({ choice: 'granted' });
    const first = readWorkspaceSettings().sightingShareConsent;
    await setSightingShareConsent({ choice: 'granted' });
    expect(readWorkspaceSettings().sightingShareConsent).toEqual(first);
  });

  it('removes the grant from the file on revoke', async () => {
    await setSightingShareConsent({ choice: 'granted' });
    expect(await setSightingShareConsent({ choice: 'revoked' })).toEqual({ ok: true });
    expect(readFileSync(settingsFile(), 'utf8')).not.toContain('sightingShareConsent');
  });

  it('refuses a malformed payload without throwing, and writes nothing', async () => {
    for (const input of [null, 42, {}, { choice: 'yes' }]) {
      const res = await setSightingShareConsent(input);
      expect(res.ok).toBe(false);
    }
    expect(existsSync(settingsFile())).toBe(false);
  });

  it('refuses a change the organization decides, and writes nothing', async () => {
    sharingState.value = {
      mode: 'machine',
      managed: false,
      sharing: false,
      reason: 'managed-denied',
      optedIn: false,
      locked: true,
      organization: 'Acme',
    };
    const res = await setSightingShareConsent({ choice: 'granted' });
    expect(res).toEqual({ ok: false, error: managedRefusal(['sightingShareConsent']) });
    expect(existsSync(settingsFile())).toBe(false);
  });
});
