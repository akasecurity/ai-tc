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

  it('renders nothing for an empty list', () => {
    const html = renderToStaticMarkup(<NeedsReviewListView items={[]} onReview={vi.fn()} />);
    expect(html).not.toContain('Review<');
  });
});
