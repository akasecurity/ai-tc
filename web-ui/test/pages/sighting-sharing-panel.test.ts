// @vitest-environment jsdom
//
// The settings card's wiring: a choice reaches the Server Action, and a refusal
// or a failed request is shown to the user.
import type { SightingSharing } from '@akasecurity/schema';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const setSightingShareConsent =
  vi.fn<(input: { choice: string }) => Promise<{ ok: boolean; error?: string }>>();
vi.mock('../../app/(app)/settings/actions', () => ({
  setSightingShareConsent: (input: { choice: string }) => setSightingShareConsent(input),
}));

const { SightingSharingPanel } = await import('../../app/(app)/settings/SightingSharingPanel.tsx');

const SCOPED: SightingSharing = {
  mode: 'scoped',
  managed: false,
  sharing: false,
  reason: 'not-opted-in',
  optedIn: false,
  locked: false,
};

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  setSightingShareConsent.mockReset();
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  act(() => {
    root.render(createElement(SightingSharingPanel, { state: SCOPED }));
  });
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

// The radios follow SIGHTING_SHARE_CHOICES: granted first, revoked second.
async function choose(value: 'granted' | 'revoked'): Promise<void> {
  const radios = container.querySelectorAll<HTMLInputElement>('input[type="radio"]');
  const input = radios[value === 'granted' ? 0 : 1];
  if (input === undefined) throw new Error(`no ${value} choice to pick`);
  await act(async () => {
    input.click();
    await Promise.resolve();
  });
}

function alertText(): string | null {
  return container.querySelector('[role="alert"]')?.textContent ?? null;
}

describe('SightingSharingPanel', () => {
  it('sends the chosen value and shows no error when it is saved', async () => {
    setSightingShareConsent.mockResolvedValue({ ok: true });
    await choose('granted');
    expect(setSightingShareConsent).toHaveBeenCalledWith({ choice: 'granted' });
    expect(alertText()).toBeNull();
  });

  it('shows the error a refused save returns', async () => {
    setSightingShareConsent.mockResolvedValue({ ok: false, error: 'Managed by Acme.' });
    await choose('granted');
    expect(alertText()).toBe('Managed by Acme.');
  });

  it('shows a generic message when a refusal carries no error', async () => {
    setSightingShareConsent.mockResolvedValue({ ok: false });
    await choose('granted');
    expect(alertText()).toBe('Could not save.');
  });

  it('shows a connection message when the request itself fails', async () => {
    setSightingShareConsent.mockRejectedValue(new Error('network'));
    await choose('granted');
    expect(alertText()).toBe('The change could not be sent — check your connection and try again.');
  });
});
