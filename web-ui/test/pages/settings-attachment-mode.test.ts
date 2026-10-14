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

  it('hands the settings to the client whole, the scope record and its binding included', async () => {
    // What the page's comment above the client says: the repositories this
    // machine enrolled and the organization and account the record is bound to
    // reach the browser. No credential is among them.
    const record = {
      endpoint: ENDPOINT,
      tenantName: 'Example Org',
      userEmail: 'operator',
      entries: [
        {
          kind: 'repo',
          identity: 'github.com/acme/payments-api',
          enrolledAt: '2026-10-01T00:00:00.000Z',
        },
      ],
    };
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT },
        attachmentScope: record,
      },
      akaHome(),
      null,
    );
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 2,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: KEY,
    });

    const props = await renderPage();

    expect(props.settings.attachmentScope).toEqual(record);
    expectNoEchoOf(JSON.stringify(props), KEY);
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

  // The sentences are compared whole, as a reader sees them, so a false sentence
  // that keeps the words a substring check looks for cannot pass. Spelled out
  // here and never imported from the view: a test that imports the sentence
  // cannot catch a change to it, and a change to one is made here too.
  const SCOPED_MODE_LINE =
    'Scoped — a personal device. Activity is sent only from repositories you enroll with `aka enroll`.';
  const MACHINE_MODE_LINE =
    'Machine-wide — an organization device. Activity from anywhere on this machine is sent.';
  const SCOPED_FORWARDING =
    'While this machine is attached as a personal device, the plugin forwards activity only from ' +
    'repositories you enroll with `aka enroll`; activity anywhere else stays on this machine. ' +
    'Whenever a session starts anywhere on this machine, in a repository or not (a browser chat ' +
    "included), the machine pulls that deployment's policy (at most every 15 minutes) and sends " +
    'it a device report (at most hourly): a device identifier, host name, versions, detection ' +
    'packs, policy counts, finding counts and dates for everything recorded on the machine, and, ' +
    'when the machine is attached as a personal device, the fact that it is one. Where a scan is ' +
    'available (the coding-agent plugins, not a browser chat), the same session start also ' +
    'checks it for device commands. A scan you run from the Scan page sends the Data ' +
    'Shares register only for an enrolled repository — destinations and call sites, never source ' +
    'text. Re-attaching with a version of AKA older than this one would make the attachment ' +
    'machine-wide. This page reads only your local store, so it cannot report what the deployment ' +
    'received. Detach to stop sending.';
  const MACHINE_FORWARDING =
    'While this machine is attached, the plugin forwards the activity that deployment is entitled ' +
    'to see. Whenever a session starts anywhere on this machine, in a repository or not (a ' +
    "browser chat included), the machine pulls that deployment's policy (at most every 15 " +
    'minutes) and sends it a device report (at most hourly): a device identifier, host name, ' +
    'versions, detection packs, policy counts, finding counts and dates for everything recorded ' +
    'on the machine, and, when the machine is attached as a personal device, the fact that it is ' +
    'one. Where a scan is available (the coding-agent plugins, not a browser chat), the same ' +
    'session start also checks it for device commands. A scan you run from the Scan page also ' +
    'sends the Data Shares register it records — destinations and call sites, ' +
    'never source text. This page reads only your local store, so it cannot report what the ' +
    'deployment received. Detach to stop sending.';

  /** The text of the element carrying `data-slot="<slot>"`, as a reader sees it, or undefined. */
  function slotText(html: string, slot: string): string | undefined {
    const match = new RegExp(`<(\\w+)[^>]*\\bdata-slot="${slot}"[^>]*>([^<]*)</\\1>`).exec(html);
    return match?.[2]
      ?.replaceAll('&#x27;', "'")
      .replaceAll('&quot;', '"')
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&amp;', '&');
  }

  it('hands a scoped mode to the form, which names it and says what is sent, word for word', () => {
    const html = render({ attachmentMode: 'scoped' });
    expect(slotText(html, 'connection-mode')).toBe(SCOPED_MODE_LINE);
    expect(slotText(html, 'connection-forwarding')).toBe(SCOPED_FORWARDING);
  });

  it('hands a machine-wide mode to the form, which names it and says what is sent, word for word, without the enroll verb', () => {
    const html = render({ attachmentMode: 'machine' });
    expect(slotText(html, 'connection-mode')).toBe(MACHINE_MODE_LINE);
    expect(slotText(html, 'connection-forwarding')).toBe(MACHINE_FORWARDING);
    expect(html).not.toContain('aka enroll');
  });

  it('hands machine-only to the attach form, which offers no choice', () => {
    const html = render({ settings: { ...attached, runMode: 'standalone' }, machineOnly: true });
    expect(html).toContain('data-slot="attach-mode-managed"');
    expect(html).not.toContain('data-slot="attach-mode"');
  });
});
