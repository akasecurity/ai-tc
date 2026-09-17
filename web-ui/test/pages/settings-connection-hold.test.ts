import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import { applyOnboarding } from '@akasecurity/persistence';
import type { ManagedSettings, WorkspaceSettings } from '@akasecurity/schema';
import { MANAGED_SETTINGS_FILENAME } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import SettingsPage from '../../app/(app)/settings/page.tsx';
import { SettingsClient } from '../../app/(app)/settings/SettingsClient.tsx';
import { tempHomes } from '../helpers/temp-home.ts';

// Whether the settings route offers a connection change the attach and detach
// actions would refuse.
//
// A PINNED mode with no lock is the case the route cannot read off the managed
// context: `lockedFields` is empty, and the context carries no pins. So the page
// asks the same decision the two actions refuse on, and hands the answer down —
// and the row withholds Detach (or, on a machine held standalone, the attach
// form) exactly as it does under a lock.
//
// The administrator is installed through the process-wide managed-settings seam,
// pointed at a file inside this test's own temp home; the machine's real managed
// file is never read.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-settings-connection-hold-');

const PINNED = 'https://pinned.example-org.internal';
const ATTACHED_AT = '2026-08-01T00:00:00.000Z';

let home: string;

const akaHome = (): string => join(home, '.aka');

function administer(overlay: ManagedSettings): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

function pinning(values: ManagedSettings['values']): ManagedSettings {
  return { specVersion: 1, organization: 'Example Org', values, lockedFields: [] };
}

type ClientProps = ComponentProps<typeof SettingsClient>;

function renderPage(): ClientProps {
  const element = SettingsPage() as ReactElement;
  const head = element.props as { children: ReactElement[] };
  const client = head.children.find((child: ReactElement) => child.type === SettingsClient);
  if (client === undefined) throw new Error('the page no longer renders SettingsClient');
  return client.props as ClientProps;
}

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
});

afterEach(() => {
  // Back to the setup file's declaration: no administrator.
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
});

describe('the settings route and a held connection', () => {
  it('reports an unmanaged connection as not held', () => {
    expect(renderPage().connectionHeld).toBe(false);
  });

  it('reports a fleet pin as held, though nothing in the managed context is locked', () => {
    administer(pinning({ runMode: 'attached', controlPlane: { endpoint: PINNED } }));
    const props = renderPage();
    expect(props.managed.lockedFields).toEqual([]);
    expect(props.settings.runMode).toBe('attached');
    expect(props.connectionHeld).toBe(true);
  });

  it('reports a mode pinned to standalone as held', () => {
    administer(pinning({ runMode: 'standalone' }));
    expect(renderPage().connectionHeld).toBe(true);
  });

  it('does not report a pin on the deployment alone as held — that detach is the user’s', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: PINNED, attachedAt: ATTACHED_AT } },
      akaHome(),
      null,
    );
    administer(pinning({ controlPlane: { endpoint: PINNED } }));
    const props = renderPage();
    expect(props.settings.runMode).toBe('attached');
    expect(props.connectionHeld).toBe(false);
  });
});

describe('SettingsClient', () => {
  const attached: WorkspaceSettings = {
    specVersion: 1,
    runMode: 'attached',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
    controlPlane: { endpoint: PINNED, attachedAt: ATTACHED_AT },
  };

  const render = (connectionHeld: boolean): string =>
    renderToStaticMarkup(
      createElement(SettingsClient, {
        settings: attached,
        managed: { present: true, organization: 'Example Org', lockedFields: [] },
        credentialState: { usable: true },
        connectionHeld,
      }),
    );

  it('hands a held connection to the form, which withholds Detach', () => {
    const html = render(true);
    expect(html).not.toContain('data-slot="detach-button"');
    expect(html).toContain('data-slot="connection-managed-notice"');
  });

  it('offers Detach when the connection is not held', () => {
    // The positive control: the same client and settings, one answer apart.
    expect(render(false)).toContain('data-slot="detach-button"');
  });
});
