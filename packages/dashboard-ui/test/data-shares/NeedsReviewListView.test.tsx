import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { NeedsReviewListView } from '../../src/data-shares/NeedsReviewListView.tsx';
import { reviewDestination } from './fixtures.ts';

describe('NeedsReviewListView', () => {
  it('renders one row per item with its name, flag reason and call count', () => {
    const html = renderToStaticMarkup(
      <NeedsReviewListView
        items={[
          reviewDestination({ id: 'a', name: '203.0.113.0', callSiteCount: 2 }),
          reviewDestination({
            id: 'b',
            name: 'unverified.example.com',
            kind: 'external',
            trust: 'unverified',
            review: { needsReview: true, reasons: ['unverified_domain'] },
            callSiteCount: 1,
          }),
        ]}
        onReview={vi.fn()}
      />,
    );
    expect(html).toContain('203.0.113.0');
    expect(html).toContain('Connects to a raw IP with no reverse DNS');
    expect(html).toContain('2 calls');
    expect(html).toContain('unverified.example.com');
    expect(html).toContain('Corporate-looking domain not owned by your org');
    expect(html).toContain('1 call<');
  });

  it('shows the host under a provider name, and not a second time where the name is the host', () => {
    const named = renderToStaticMarkup(
      <NeedsReviewListView
        items={[
          reviewDestination({
            id: 'a',
            name: 'Okta',
            host: 'okta.com',
            kind: 'provider',
            trust: 'recognized',
            providerId: 'okta',
          }),
        ]}
        onReview={vi.fn()}
      />,
    );
    expect(named).toContain('Okta');
    expect(named).toContain('okta.com');

    const ip = renderToStaticMarkup(
      <NeedsReviewListView
        items={[reviewDestination({ id: 'b', name: '203.0.113.0', host: '203.0.113.0' })]}
        onReview={vi.fn()}
      />,
    );
    expect(ip.split('203.0.113.0')).toHaveLength(2);
  });

  it('says the queue is clear for an empty list, rather than rendering a blank body', () => {
    // The sheet outlives its own list — the last flagged destination can clear
    // while it is still open — so an empty list has to say something.
    const html = renderToStaticMarkup(<NeedsReviewListView items={[]} onReview={vi.fn()} />);
    expect(html).toContain('Nothing needs review');
    expect(html).not.toContain('Review<');
  });
});
