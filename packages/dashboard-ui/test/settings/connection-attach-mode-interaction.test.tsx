// @vitest-environment jsdom
//
// The attach form's mode choice, driven through real input. A server render
// cannot type into a field, so it cannot see the one property that matters
// here: Attach stays disabled until a mode is chosen, and the mode that leaves
// is the one on screen.
import type { AttachmentMode, WorkspaceSettings } from '@akasecurity/schema';
import { act } from 'react';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { WorkspaceSettingsFormView } from '../../src/settings/WorkspaceSettingsFormView.tsx';
import {
  type MountedRoot,
  mountRoot,
  renderRoot,
  unmountMountedRoot,
} from '../helpers/react-root.ts';

const ENDPOINT = 'https://aka.example.com';

const standalone: WorkspaceSettings = {
  specVersion: 1,
  runMode: 'standalone',
  policy: 'redact',
  historicalAccess: 'session-only',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
  redactFallback: 'warn',
  bodyRetention: { enabled: false, retainDays: 30 },
};

const attached: WorkspaceSettings = {
  ...standalone,
  runMode: 'attached',
  controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-10-01T00:00:00.000Z' },
};

let mounted: MountedRoot;
/** Every attach the view handed to the host, as the argument list it passed. */
let sent: unknown[][];

beforeEach(() => {
  mounted = mountRoot();
  sent = [];
});

afterEach(() => {
  unmountMountedRoot(mounted);
});

function render(
  props: {
    settings?: WorkspaceSettings;
    attachmentMode?: AttachmentMode;
    machineOnly?: boolean;
  } = {},
): void {
  renderRoot(
    mounted.root,
    <WorkspaceSettingsFormView
      settings={props.settings ?? standalone}
      onSave={() => undefined}
      onAttach={(...args) => {
        sent.push(args);
      }}
      attachmentMode={props.attachmentMode}
      machineOnly={props.machineOnly}
    />,
  );
}

// The value goes through the prototype's setter before the event is
// dispatched: React tracks the value it last saw and skips a change event that
// does not differ from it (dismiss-dialog.test.tsx measures this).
const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

function typeInto(label: string, value: string): void {
  const input = mounted.host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
  if (input === null) throw new Error(`no input labelled ${label}`);
  // A property descriptor's `set`, applied with an explicit receiver below.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const setter = valueDescriptor?.set;
  if (setter === undefined) throw new Error('HTMLInputElement has no value setter');
  act(() => {
    Reflect.apply(setter, input, [value]);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

function attachButton(): HTMLButtonElement {
  const button = mounted.host.querySelector<HTMLButtonElement>('[data-slot="attach-button"]');
  if (button === null) throw new Error('the attach button is not on the page');
  return button;
}

function radio(label: string): HTMLInputElement {
  const card = [...mounted.host.querySelectorAll('[data-slot="attach-mode"] label')].find((el) =>
    el.textContent.includes(label),
  );
  const input = card?.querySelector<HTMLInputElement>('input[type="radio"]') ?? null;
  if (input === null) throw new Error(`no mode choice labelled ${label}`);
  return input;
}

function click(el: HTMLElement): void {
  act(() => {
    el.click();
  });
}

describe('the attach form and its mode', () => {
  it('keeps Attach disabled until a mode is chosen, then sends the one chosen', () => {
    render();
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    expect(attachButton().disabled).toBe(true);

    click(radio('Personal device'));
    expect(attachButton().disabled).toBe(false);
    click(attachButton());

    expect(sent).toEqual([[ENDPOINT, '', 'test-key', 'scoped']]);
  });

  it('sends the organization-device choice as machine', () => {
    render();
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    click(radio('Organization device'));
    click(attachButton());

    expect(sent).toEqual([[ENDPOINT, '', 'test-key', 'machine']]);
  });

  it('offers no choice on a machine held machine-wide, and attaches with no mode', () => {
    render({ machineOnly: true });
    expect(mounted.host.querySelector('[data-slot="attach-mode"]')).toBeNull();
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    expect(attachButton().disabled).toBe(false);
    click(attachButton());

    // Three arguments: the action decides machine-wide on its own server-side
    // read, so the form asserts nothing about the mode.
    expect(sent).toEqual([[ENDPOINT, '', 'test-key']]);
  });

  it('defaults to the mode kept for the endpoint the settings name, and only for it', () => {
    render({
      settings: {
        ...standalone,
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-10-01T00:00:00.000Z' },
      },
      attachmentMode: 'scoped',
    });
    typeInto('Access key', 'test-key');
    typeInto('Deployment endpoint', 'https://other.example.com');
    expect(attachButton().disabled).toBe(true);

    typeInto('Deployment endpoint', ENDPOINT);
    expect(radio('Personal device').checked).toBe(true);
    expect(attachButton().disabled).toBe(false);
    click(attachButton());

    expect(sent).toEqual([[ENDPOINT, '', 'test-key', 'scoped']]);
  });

  it('forgets a pick when the machine is attached and then detached outside this page', () => {
    render();
    click(radio('Personal device'));
    expect(radio('Personal device').checked).toBe(true);

    // The machine attaches and detaches elsewhere while this page stays open,
    // so the page re-renders in place without the in-page Detach ever running.
    render({ settings: attached });
    render();

    expect(radio('Personal device').checked).toBe(false);
    expect(radio('Organization device').checked).toBe(false);
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    expect(attachButton().disabled).toBe(true);
  });
});
