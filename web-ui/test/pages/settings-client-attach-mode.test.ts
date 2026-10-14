// @vitest-environment jsdom
//
// The device kind chosen on the attach form reaches the attach action. The view
// suite proves the form hands its choice to `onAttach`, and the action suite
// proves the action honours the `mode` it is given; neither sees the client
// component between them, which is where a dropped `mode` would turn a personal
// device into a machine-wide attachment without anyone choosing it.
import { NO_MANAGED_CONTEXT, type WorkspaceSettings } from '@akasecurity/schema';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The page's own Server Actions cannot run here: the attach is replaced by a
// spy that records the input it was called with.
const attachToControlPlane = vi.fn<(input: unknown) => Promise<{ ok: boolean }>>();
vi.mock('../../app/(app)/settings/actions', () => ({
  attachToControlPlane: (input: unknown) => attachToControlPlane(input),
  detachFromControlPlane: vi.fn(),
  saveSettings: vi.fn(),
}));

const { SettingsClient } = await import('../../app/(app)/settings/SettingsClient.tsx');

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

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  attachToControlPlane.mockReset();
  attachToControlPlane.mockResolvedValue({ ok: true });
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

function mount(machineOnly?: boolean): void {
  act(() => {
    root.render(
      createElement(SettingsClient, {
        settings: standalone,
        managed: NO_MANAGED_CONTEXT,
        credentialState: { usable: true },
        connectionHeld: false,
        machineOnly,
      }),
    );
  });
}

// The value goes through the prototype's setter before the event is dispatched:
// React tracks the value it last saw and skips a change event that does not
// differ from it.
const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

function typeInto(label: string, value: string): void {
  const input = container.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
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

function choose(label: string): void {
  const card = [...container.querySelectorAll('[data-slot="attach-mode"] label')].find((el) =>
    el.textContent.includes(label),
  );
  const radio = card?.querySelector<HTMLInputElement>('input[type="radio"]') ?? null;
  if (radio === null) throw new Error(`no mode choice labelled ${label}`);
  act(() => {
    radio.click();
  });
}

async function clickAttach(): Promise<void> {
  const button = container.querySelector<HTMLButtonElement>('[data-slot="attach-button"]');
  if (button === null) throw new Error('the attach button is not on the page');
  await act(async () => {
    button.click();
    await Promise.resolve();
  });
}

/** The one input the attach action was called with. */
function attachInput(): Record<string, unknown> {
  expect(attachToControlPlane).toHaveBeenCalledTimes(1);
  return attachToControlPlane.mock.calls[0]?.[0] as Record<string, unknown>;
}

describe('SettingsClient and the attach input', () => {
  it('sends a personal device as the scoped mode', async () => {
    mount();
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    choose('Personal device');
    await clickAttach();

    expect(attachInput()).toEqual({
      endpoint: ENDPOINT,
      label: '',
      accessKey: 'test-key',
      mode: 'scoped',
    });
  });

  it('sends an organization device as the machine mode', async () => {
    mount();
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    choose('Organization device');
    await clickAttach();

    expect(attachInput()).toEqual({
      endpoint: ENDPOINT,
      label: '',
      accessKey: 'test-key',
      mode: 'machine',
    });
  });

  it('names no mode at all on a machine held machine-wide', async () => {
    mount(true);
    typeInto('Deployment endpoint', ENDPOINT);
    typeInto('Access key', 'test-key');
    await clickAttach();

    // Absent, not undefined: the action decides from its own read of the machine.
    expect(Object.keys(attachInput())).not.toContain('mode');
  });
});
