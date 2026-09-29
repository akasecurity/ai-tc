// The web half of the marketplace-pin explanation.
//
// `latest` is the version the HOST will install, which for a plugin resolved
// through a marketplace manifest is that manifest's pin rather than npm's
// latest. The CLI prints why; without this the page shows the installed
// version, a green badge and nothing else — indistinguishable from a report
// that is simply stale, which is the ambiguity carrying the pin here removes.
import type { ComponentStatus } from '@akasecurity/schema';
import { MANAGED_PLUGIN_ADVICE } from '@akasecurity/schema';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { UpdateStatusCardView } from '../../src/updates/UpdateStatusCardView.tsx';

const status = (over: Partial<ComponentStatus> = {}): ComponentStatus => ({
  id: 'claude-code',
  name: 'Claude Code plugin',
  kind: 'plugin',
  installed: '0.9.9',
  latest: '0.9.9',
  updateAvailable: false,
  ...over,
});

const render = (s: ComponentStatus): string =>
  renderToStaticMarkup(
    createElement(UpdateStatusCardView, {
      statuses: [s],
      checkedAt: null,
      onCheckNow: () => undefined,
      onApply: () => undefined,
      applyingId: null,
      outcomes: {},
      restartRequired: false,
    }),
  );

const NOTE = 'data-slot="marketplace-pin-note"';

describe('UpdateStatusCardView — the marketplace-pin note', () => {
  it('renders the row at all, so the absences below are not vacuous', () => {
    const html = render(status());

    expect(html).toContain('Claude Code plugin');
    expect(html).toContain('0.9.9');
  });

  it('explains a pin that is behind npm, naming the marketplace that has to move', () => {
    const html = render(
      status({
        marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.10', npmAhead: true },
      }),
    );

    expect(html).toContain(NOTE);
    expect(html).toContain('akasecurity');
    expect(html).toContain('0.9.10');
  });

  it.each([
    [
      'a pin npm has not moved past',
      { marketplace: 'akasecurity', npmLatest: '0.9.9', npmAhead: false },
    ],
    ['a pin with no npm answer', { marketplace: 'akasecurity', npmLatest: null, npmAhead: false }],
  ])('says nothing about %s, which explains nothing', (_label, marketplacePin) => {
    expect(render(status({ marketplacePin }))).not.toContain(NOTE);
  });

  // A range is not orderable against npm, so `npmAhead` is false for one — and
  // the exact-pin rule above would say nothing while the row shows npm's answer
  // beside a status the host, resolving within the range, may never reach.
  it('explains a range pin, naming the range and the marketplace', () => {
    const html = render(
      status({
        marketplacePin: {
          marketplace: 'akasecurity',
          npmLatest: '0.12.0',
          npmAhead: false,
          range: '^0.11.0-beta.0',
        },
      }),
    );

    expect(html).toContain(NOTE);
    expect(html).toContain('^0.11.0-beta.0');
    expect(html).toContain('akasecurity');
    expect(html).toContain('0.12.0');
  });

  it('says nothing when there is no pin', () => {
    expect(render(status())).not.toContain(NOTE);
  });

  it('says nothing when the pinned latest is unknown', () => {
    // Comparing against an unknown would be inventing a gap.
    expect(
      render(
        status({
          latest: null,
          marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.10', npmAhead: true },
        }),
      ),
    ).not.toContain(NOTE);
  });
});

// A plugin an organization's managed settings installed. The report never
// offers it as an update, so the card must not either — and has to say who
// moves it, or a row behind the organization's pin reads as a stale page.
describe('UpdateStatusCardView — an install an organization manages', () => {
  const MANAGED_NOTE = 'data-slot="managed-install-note"';
  const managed = (over: Partial<ComponentStatus> = {}): ComponentStatus =>
    status({
      installed: '0.9.13',
      latest: '0.9.14',
      managedInstall: { ref: 'org-release-8', pending: true },
      ...over,
    });

  it('offers no Update button and badges the row as managed', () => {
    const html = render(managed());

    // The positive control: the row itself rendered.
    expect(html).toContain('Claude Code plugin');
    expect(html).not.toContain('>Update<');
    expect(html).not.toContain('update available');
    expect(html).toContain('>managed<');
  });

  it('names what is on its way and the route that delivers it', () => {
    const html = render(managed());

    expect(html).toContain(MANAGED_NOTE);
    expect(html).toContain('0.9.13 → 0.9.14');
    expect(html).toContain('org-release-8');
    expect(html).toContain('v0.9.14 is on its way.');
    // Rendered text, so compare against the HTML-escaped wording.
    expect(html).toContain(MANAGED_PLUGIN_ADVICE.replaceAll("'", '&#x27;'));
  });

  it('explains a current managed install without claiming anything is on its way', () => {
    const html = render(managed({ installed: '0.9.14', managedInstall: { pending: false } }));

    expect(html).toContain(MANAGED_NOTE);
    expect(html).not.toContain('on its way');
    // The version arrow specifically: the advice itself spells `/plugin → update`.
    expect(html).not.toContain(' → 0.9.14');
    expect(html).toContain('0.9.14');
  });

  it('explains the row once, not also as a marketplace pin', () => {
    const html = render(
      managed({
        marketplacePin: { marketplace: 'akasecurity', npmLatest: '0.9.15', npmAhead: true },
      }),
    );

    expect(html).toContain(MANAGED_NOTE);
    expect(html).not.toContain(NOTE);
  });

  it('keeps the Update button for a row nobody manages (positive control)', () => {
    const html = render(status({ installed: '0.9.13', latest: '0.9.14', updateAvailable: true }));

    expect(html).toContain('>Update<');
    expect(html).not.toContain(MANAGED_NOTE);
  });
});
