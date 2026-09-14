// The web half of the marketplace-pin explanation.
//
// `latest` is the version the HOST will install, which for a plugin resolved
// through a marketplace manifest is that manifest's pin rather than npm's
// latest. The CLI prints why; without this the page shows the installed
// version, a green badge and nothing else — indistinguishable from a report
// that is simply stale, which is the ambiguity carrying the pin here removes.
import type { ComponentStatus } from '@akasecurity/schema';
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
