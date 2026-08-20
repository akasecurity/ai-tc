import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';

import { NeedsReviewStripView } from '../../src/data-shares/NeedsReviewStripView.tsx';
import { reviewDestination } from './fixtures.ts';

describe('NeedsReviewStripView', () => {
  it('renders nothing when nothing is flagged', () => {
    const html = renderToStaticMarkup(<NeedsReviewStripView items={[]} onOpen={vi.fn()} />);
    expect(html).toBe('');
  });

  it('shows the flagged count', () => {
    const html = renderToStaticMarkup(
      <NeedsReviewStripView
        items={[reviewDestination({ id: 'a' }), reviewDestination({ id: 'b' })]}
        onOpen={vi.fn()}
      />,
    );
    expect(html).toContain('Needs review');
    expect(html).toContain('>2<');
  });

  it('announces that it opens a dialog', () => {
    // The strip opens a focus-trapping Sheet. Without this a screen-reader
    // user gets no warning before focus is taken.
    const html = renderToStaticMarkup(
      <NeedsReviewStripView items={[reviewDestination()]} onOpen={vi.fn()} />,
    );
    expect(html).toContain('aria-haspopup="dialog"');
  });
});
