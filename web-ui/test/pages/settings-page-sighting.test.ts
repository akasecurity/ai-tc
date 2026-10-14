import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { SightingSharing } from '@akasecurity/schema';
import type { ReactElement } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import SettingsPage from '../../app/(app)/settings/page.tsx';
import { SightingSharingPanel } from '../../app/(app)/settings/SightingSharingPanel.tsx';
import { tempHomes } from '../helpers/temp-home.ts';

const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

const newHome = tempHomes('aka-settings-sighting-');

beforeEach(() => {
  osHome.dir = newHome();
});

async function sharingState(): Promise<SightingSharing> {
  const element = (await SettingsPage()) as ReactElement;
  const { children } = element.props as { children: ReactElement[] };
  const panel = children.find((child) => child.type === SightingSharingPanel);
  if (panel === undefined) throw new Error('the page no longer renders SightingSharingPanel');
  return (panel.props as { state: SightingSharing }).state;
}

describe('the settings route — credential sightings', () => {
  it('hands the panel a standalone state on a machine that never attached', async () => {
    expect(await sharingState()).toMatchObject({
      mode: 'standalone',
      sharing: false,
      reason: 'standalone',
    });
  });

  it('reads the mode from the attach credential', async () => {
    const base = join(osHome.dir, '.aka');
    const endpoint = 'https://aka.acme.internal';
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-02-02T00:00:00.000Z' } },
      base,
      null,
    );
    writeControlPlaneCredential(settingsDir(base), {
      specVersion: 1,
      endpoint,
      apiKey: 'placeholder',
      mintedAt: '2026-02-02T00:00:00.000Z',
    });
    const state = await sharingState();
    expect(state).toMatchObject({ mode: 'machine', sharing: false, reason: 'not-opted-in' });
    expect(JSON.stringify(state)).not.toContain('placeholder');
  });
});
