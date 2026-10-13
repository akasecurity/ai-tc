import type { SightingSharing } from '@akasecurity/schema';
import { SIGHTING_SHARE_PAYLOAD_NOTE } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import {
  SIGHTING_SHARE_CHOICES,
  SightingSharingView,
} from '../../src/settings/SightingSharingView.tsx';

const state = (over: Partial<SightingSharing> = {}): SightingSharing => ({
  mode: 'scoped',
  managed: false,
  sharing: false,
  reason: 'not-opted-in',
  optedIn: false,
  locked: false,
  ...over,
});

const render = (s: SightingSharing): string =>
  renderToStaticMarkup(<SightingSharingView state={s} onChange={() => undefined} />);

const radios = (html: string): string[] => html.match(/<input[^>]*type="radio"[^>]*>/g) ?? [];

/** The choice whose radio is checked, by its position in SIGHTING_SHARE_CHOICES. */
const checkedChoice = (html: string): string | undefined =>
  SIGHTING_SHARE_CHOICES[radios(html).findIndex((i) => i.includes('checked'))]?.value;

describe('SightingSharingView', () => {
  it('states the mode, whether sharing is on and why, and the payload limit', () => {
    const html = render(state());
    expect(html).toContain('Credential sightings');
    expect(html).toContain('Off');
    expect(html).toContain('attached, scoped');
    expect(html).toContain('You have not opted in.');
    expect(html).toContain(SIGHTING_SHARE_PAYLOAD_NOTE);
  });

  it('offers an editable toggle that reflects the user own grant', () => {
    const html = render(state({ optedIn: true, sharing: true, reason: 'opted-in' }));
    const inputs = radios(html);
    expect(inputs).toHaveLength(SIGHTING_SHARE_CHOICES.length);
    for (const input of inputs) expect(input).not.toContain('disabled');
    expect(inputs.filter((i) => i.includes('checked'))).toHaveLength(1);
    expect(checkedChoice(html)).toBe('granted');
    expect(html).toContain('On');
  });

  it('renders locked when the organization requires sharing', () => {
    const html = render(
      state({
        mode: 'machine',
        managed: true,
        sharing: true,
        locked: true,
        reason: 'managed-required',
        organization: 'Acme',
      }),
    );
    expect(html).toContain('data-slot="managed-notice"');
    expect(html).toContain('Managed by Acme. This setting cannot be changed here.');
    expect(html).toContain('Required by Acme on this managed machine.');
    for (const input of radios(html)) expect(input).toContain('disabled');
    expect(checkedChoice(html)).toBe('granted');
  });

  it('renders locked and off under a hard deny, whatever the user granted', () => {
    const html = render(
      state({ optedIn: true, locked: true, reason: 'managed-denied', organization: 'Acme' }),
    );
    expect(html).toContain('Turned off by Acme.');
    for (const input of radios(html)) expect(input).toContain('disabled');
    expect(checkedChoice(html)).toBe('revoked');
  });

  it('says a standalone machine shares nothing, and keeps the toggle', () => {
    const html = render(state({ mode: 'standalone', reason: 'standalone', optedIn: true }));
    expect(html).toContain('This machine is not attached to an organization.');
    expect(html).toContain('standalone');
    expect(radios(html).some((i) => i.includes('disabled'))).toBe(false);
  });

  it('shows an error when one is given', () => {
    const html = renderToStaticMarkup(
      <SightingSharingView state={state()} onChange={() => undefined} error="Could not save." />,
    );
    expect(html).toContain('Could not save.');
  });
});
