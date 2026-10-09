import { randomBytes } from 'node:crypto';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AttachedCredentialAny } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import ScanPage from '../../app/(app)/scan/page.tsx';
import { ScanClient } from '../../app/(app)/scan/ScanClient.tsx';
import { tempHomes } from '../helpers/temp-home.ts';

// The Scan page says before a click whether this scan's register will be sent.
// On a scoped machine it goes only for an enrolled project, so the page hands
// the client the attachment's mode, read server-side, beside the deployment's
// name.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// Homes are removed when this FILE finishes, not after each test. See the helper.
const newHome = tempHomes('aka-scan-attachment-mode-');

const ENDPOINT = 'https://aka.example.com';
const KEY = randomBytes(24).toString('base64url');

let home: string;

const akaHome = (): string => join(home, '.aka');

function attachWith(credential: AttachedCredentialAny): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: ENDPOINT,
        label: 'Acme Prod',
        attachedAt: '2026-10-01T00:00:00.000Z',
      },
    },
    akaHome(),
    null,
  );
  writeControlPlaneCredential(settingsDir(akaHome()), credential);
}

type ClientProps = ComponentProps<typeof ScanClient>;

function renderPage(): ClientProps {
  const element = ScanPage() as ReactElement;
  const children = (element.props as { children: ReactElement[] }).children;
  const client = children.find((child: ReactElement) => child.type === ScanClient);
  if (client === undefined) throw new Error('the page no longer renders ScanClient');
  return client.props as ClientProps;
}

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
});

describe('the Scan page and the attachment mode', () => {
  it('reports no deployment and no mode on a standalone install', () => {
    const props = renderPage();
    expect(props.attachedTo).toBeNull();
    expect(props.attachmentMode).toBeUndefined();
  });

  it('names the deployment and the scoped mode on a scoped machine', () => {
    attachWith({ specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY });
    const props = renderPage();
    expect(props.attachedTo).toBe('Acme Prod');
    expect(props.attachmentMode).toBe('scoped');
  });

  it('reports machine on a machine-wide machine', () => {
    attachWith({ specVersion: 1, endpoint: ENDPOINT, apiKey: KEY });
    expect(renderPage().attachmentMode).toBe('machine');
  });
});
