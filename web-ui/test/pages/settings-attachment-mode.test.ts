import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type {
  AttachedCredentialAny,
  ManagedSettings,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { MANAGED_SETTINGS_FILENAME, NO_MANAGED_CONTEXT } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../packages/persistence/src/managed-settings.ts';
import SettingsPage from '../../app/(app)/settings/page.tsx';
import { SettingsClient } from '../../app/(app)/settings/SettingsClient.tsx';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// What the settings route tells the form about the attachment's MODE, and what
// it never tells it: the key. The mode is read server-side from the credential
// and handed down alone; whether a scoped attach is refused here is decided by
// the rule the attach action refuses on.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-settings-attachment-mode-');

const ENDPOINT = 'https://aka.example.com';
const ATTACHED_AT = '2026-10-01T00:00:00.000Z';
const KEY = randomBytes(24).toString('base64url');

let home: string;

const akaHome = (): string => join(home, '.aka');

function attachWith(credential: AttachedCredentialAny): void {
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT } },
    akaHome(),
    null,
  );
  writeControlPlaneCredential(settingsDir(akaHome()), credential);
}

function administer(overlay: ManagedSettings): void {
  const dir = join(home, 'administrator');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, MANAGED_SETTINGS_FILENAME);
  writeFileSync(file, JSON.stringify(overlay));
  UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
}

type ClientProps = ComponentProps<typeof SettingsClient>;

async function renderPage(): Promise<ClientProps> {
  const element = (await SettingsPage()) as ReactElement;
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

describe('the settings route and the attachment mode', () => {
  it('reports no mode on a standalone machine, and nothing held to machine-wide', async () => {
    const props = await renderPage();
    expect(props.attachmentMode).toBeUndefined();
    expect(props.machineOnly).toBe(false);
  });

  it('reports scoped for a scoped credential', async () => {
    attachWith({ specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY });
    expect((await renderPage()).attachmentMode).toBe('scoped');
  });

  it('reports machine for a machine-wide credential', async () => {
    attachWith({ specVersion: 1, endpoint: ENDPOINT, apiKey: KEY });
    expect((await renderPage()).attachmentMode).toBe('machine');
  });

  it('reports no mode for a credential issued for another deployment', async () => {
    attachWith({
      specVersion: 2,
      mode: 'scoped',
      endpoint: 'https://other.example.com',
      apiKey: KEY,
    });
    expect((await renderPage()).attachmentMode).toBeUndefined();
  });

  it('reports machine-only under a pin on the connection alone, which holds nothing', async () => {
    administer({
      specVersion: 1,
      organization: 'Example Org',
      values: { controlPlane: { endpoint: ENDPOINT } },
      lockedFields: [],
    });
    const props = await renderPage();
    expect(props.machineOnly).toBe(true);
    expect(props.connectionHeld).toBe(false);
  });

  it('never hands the key to the client component', async () => {
    attachWith({ specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY });
    expectNoEchoOf(JSON.stringify(await renderPage()), KEY);
  });
});

describe('SettingsClient and the mode', () => {
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
    controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT },
  };

  const render = (props: Partial<ClientProps>): string =>
    renderToStaticMarkup(
      createElement(SettingsClient, {
        settings: attached,
        managed: NO_MANAGED_CONTEXT,
        credentialState: { usable: true },
        connectionHeld: false,
        ...props,
      }),
    );

  it('hands a scoped mode to the form, which names it and says to enroll', () => {
    const html = render({ attachmentMode: 'scoped' });
    expect(html).toContain('data-slot="connection-mode"');
    expect(html).toContain('aka enroll');
  });

  it('hands a machine-wide mode to the form, which names it without the enroll verb', () => {
    const html = render({ attachmentMode: 'machine' });
    expect(html).toContain('data-slot="connection-mode"');
    expect(html).not.toContain('aka enroll');
  });

  it('hands machine-only to the attach form, which offers no choice', () => {
    const html = render({ settings: { ...attached, runMode: 'standalone' }, machineOnly: true });
    expect(html).toContain('data-slot="attach-mode-managed"');
    expect(html).not.toContain('data-slot="attach-mode"');
  });
});
