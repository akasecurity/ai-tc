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

  it('renders the scope qualifier when one is given', () => {
    const html = renderToStaticMarkup(
      <NeedsReviewStripView items={[reviewDestination()]} onOpen={vi.fn()} scope="All destinations" />,
    );
    expect(html).toContain('All destinations');
  });

  it('omits the scope qualifier entirely when none is given', () => {
    // The prop is optional precisely because an app with nothing filtering the
    // set below the strip has no wider number to distinguish — it must not pay
    // an empty element for the ones that do. Counted as a differential rather
    // than asserted against the qualifier's own classes or its neighbours':
    // a restyle would turn either of those into a false green, where one span
    // appearing or not is the thing actually being claimed.
    const spans = (html: string) => (html.match(/<span/g) ?? []).length;
    const without = renderToStaticMarkup(
      <NeedsReviewStripView items={[reviewDestination()]} onOpen={vi.fn()} />,
    );
    const withScope = renderToStaticMarkup(
      <NeedsReviewStripView items={[reviewDestination()]} onOpen={vi.fn()} scope="All destinations" />,
    );
    expect(without).not.toContain('All destinations');
    expect(spans(withScope)).toBe(spans(without) + 1);
  });

  it('keeps the scope qualifier readable, not an icon-only hint', () => {
    // The count and the table underneath disagree on purpose. That only reads
    // as intentional if the qualifier is real text every reader gets.
    const html = renderToStaticMarkup(
      <NeedsReviewStripView
        items={[reviewDestination({ id: 'a' }), reviewDestination({ id: 'b' })]}
        onOpen={vi.fn()}
        scope="All destinations"
      />,
    );
    expect(html).not.toContain('sr-only');
    // The qualifier belongs to the count, so it renders between the count and
    // the description rather than trailing the sentence.
    expect(html.indexOf('>2<')).toBeLessThan(html.indexOf('All destinations'));
    expect(html.indexOf('All destinations')).toBeLessThan(html.indexOf('Raw IPs'));
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
