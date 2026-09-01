import { mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { ComponentProps, ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import SettingsPage from '../../app/(app)/settings/page.tsx';
import { SettingsClient } from '../../app/(app)/settings/SettingsClient.tsx';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

type ReadEffectiveArgs = Parameters<typeof Persistence.readEffectiveSettings>;

// The settings route reads the EFFECTIVE settings — the user's file with any
// administrator's overlay applied — and hands both halves down.
//
// The wiring is what nothing else can see. Reading the raw user file here
// instead would render an editable control for a value the writer then refuses,
// and every type, lint and copy assertion would stay green: the page still
// compiles, the form still renders, the control just lies about who decides.
//
// An async Server Component is a plain function returning an element, so calling
// it and reading the props it passes needs no renderer and no DOM.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// The managed layer lives at absolute SYSTEM paths, outside the home this suite
// redirects — deliberately, since a lock inside ~ is removable by the party being
// locked. So a temp home cannot make a machine look managed, and on an
// unmanaged runner the effective read and the raw read return the same thing.
//
// That is what makes the plain assertions below insufficient on their own: a
// page that read the RAW file and fabricated an unmanaged context would satisfy
// every one of them. This seam is the part that can tell the two apart — it
// records which reader the page called and lets one case answer as a managed
// machine, which the raw reader has no way to produce.
const managedSource = vi.hoisted(() => ({
  calls: 0,
  override: null as { present: boolean; organization?: string; lockedFields: string[] } | null,
}));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readEffectiveSettings: (...args: ReadEffectiveArgs) => {
      managedSource.calls += 1;
      const real = actual.readEffectiveSettings(...args);
      return managedSource.override === null ? real : { ...real, managed: managedSource.override };
    },
  };
});

const NOW = '2026-02-02T00:00:00.000Z';

let home: string;

/** The AKA home inside the redirected HOME — what every writer here takes as
 * its base, and what the page resolves for itself from `homedir()`. */
const akaHome = (): string => join(home, '.aka');

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-settings-page-'));
  osHome.dir = home;
  managedSource.calls = 0;
  managedSource.override = null;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

type ClientProps = ComponentProps<typeof SettingsClient>;

function renderPage(): ClientProps {
  const element = SettingsPage() as ReactElement;
  // Assert the shape alongside the props: a page that starts returning a
  // different wrapper would otherwise read every prop below as undefined.
  const head = element.props as { children: ReactElement[] };
  const client = head.children.find((child: ReactElement) => child.type === SettingsClient);
  // Named rather than asserted away: a page that stops rendering the client
  // must fail HERE, not read every prop below as undefined.
  if (client === undefined) throw new Error('the page no longer renders SettingsClient');
  return client.props as ClientProps;
}

describe('the settings route', () => {
  it('hands the client both the settings and the managed context', () => {
    const props = renderPage();
    expect(props.settings).toBeDefined();
    // Not merely truthy — the managed half must be a real context, or the form
    // falls back to its unmanaged default and every control renders editable.
    expect(props.managed).toBeDefined();
    expect(props.managed.lockedFields).toEqual([]);
  });

  it('reports an ordinary machine as unmanaged', () => {
    // No administrator has placed a file at the system locations on a test
    // runner, so this is the honest answer and the one the form needs.
    expect(renderPage().managed.present).toBe(false);
  });

  it('reads the EFFECTIVE settings, not the user file alone', () => {
    // The wiring assertion. A page reading readWorkspaceSettings and building
    // its own empty context passes every other case in this file, because an
    // unmanaged machine makes the two readers agree.
    renderPage();
    expect(managedSource.calls).toBe(1);
  });

  // ─── The credential half ───────────────────────────────────────────────────
  //
  // `runMode: 'attached'` is a stored answer; whether the machine can use the
  // connection also depends on a credential file. Without this prop the form
  // renders "Attached" for a machine that sends and receives nothing, which is
  // the state `aka status` has always been able to name and this page could
  // not.

  it('hands the client the credential state', () => {
    const props = renderPage();
    // A fresh temp home has no credential file, which is the ordinary
    // standalone answer — the form ignores it while standalone.
    expect(props.credentialState).toEqual({ usable: false, reason: 'absent' });
  });

  it('reports a missing credential on a machine whose settings say attached', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://aka.acme.internal', attachedAt: NOW },
      },
      akaHome(),
    );
    const props = renderPage();
    expect(props.settings.runMode).toBe('attached');
    expect(props.credentialState).toEqual({ usable: false, reason: 'absent' });
  });

  // The wiring assertion that nothing else can make. Passing the descriptor to
  // the reader is the ONLY thing that makes a mismatch detectable: a credential
  // minted for another deployment parses perfectly, so a page that read the
  // credential without the descriptor would report it usable and every other
  // case in this file would still pass.
  it('detects a credential minted for a different deployment', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://new.acme.internal', attachedAt: NOW },
      },
      akaHome(),
    );
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://old.acme.internal',
      apiKey: 'a-key-for-the-old-deployment',
    });
    expect(renderPage().credentialState).toEqual({
      usable: false,
      reason: 'endpoint-mismatch',
      credentialEndpoint: 'https://old.acme.internal',
      settingsEndpoint: 'https://new.acme.internal',
    });
  });

  it('reports a matching credential as usable', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://aka.acme.internal', attachedAt: NOW },
      },
      akaHome(),
    );
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://aka.acme.internal',
      apiKey: 'a-key-for-this-deployment',
    });
    const state = renderPage().credentialState;
    expect(state.usable).toBe(true);
  });

  // THE KEY MUST NOT CROSS THIS BOUNDARY, and asserting `usable === true` above
  // cannot see whether it did — which is exactly why it once did. `SettingsClient`
  // is `'use client'`, so every prop reaching it is serialised into the payload
  // the browser receives on each settings render; a `credentialState` whose
  // usable branch carried an `AttachedCredential` put a bearer key in there on
  // every visit.
  //
  // Asserted over the SERIALISED prop rather than by naming the field, so it
  // stays red for any future shape that reintroduces the value under another
  // name or nested one level down.
  it('hands the client no part of the key, on the branch that used to carry it', () => {
    const apiKey = 'zq7fvkxm2rjt9wbn4hdc6sylp3g8';
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://aka.acme.internal', attachedAt: NOW },
      },
      akaHome(),
    );
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://aka.acme.internal',
      apiKey,
    });
    const serialised = JSON.stringify(renderPage().credentialState);
    // A positive control first: `expectNoEchoOf` passes trivially over bytes
    // that came back empty, and an empty serialisation is the one way this
    // assertion could be green while proving nothing.
    expect(serialised).toContain('"usable":true');
    expectNoEchoOf(serialised, apiKey);
  });

  it('passes an administrator’s locks straight through to the form', () => {
    // And the consequence: on a managed machine the form must receive the real
    // locked set. A fabricated context renders every control editable, and the
    // writer then refuses the save the user was invited to make.
    managedSource.override = {
      present: true,
      organization: 'Acme',
      lockedFields: ['runMode', 'vaultConsent'],
    };
    const props = renderPage();
    expect(props.managed.present).toBe(true);
    expect(props.managed.organization).toBe('Acme');
    expect(props.managed.lockedFields).toEqual(['runMode', 'vaultConsent']);
  });

  it('passes through what the user actually chose', () => {
    applyOnboarding({ historicalAccess: 'full', vaultInlineReveal: 'off' }, join(home, '.aka'));
    const props = renderPage();
    expect(props.settings.historicalAccess).toBe('full');
    expect(props.settings.vaultInlineReveal).toBe('off');
  });

  it('carries the attached connection through to the form', () => {
    // The connection section renders from these two fields together; a page
    // that dropped the descriptor would show the machine as standalone.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint: 'https://aka.acme.internal',
          label: 'Acme Prod',
          attachedAt: '2026-02-02T00:00:00.000Z',
        },
      },
      join(home, '.aka'),
    );
    const props = renderPage();
    expect(props.settings.runMode).toBe('attached');
    expect(props.settings.controlPlane?.label).toBe('Acme Prod');
  });
});
