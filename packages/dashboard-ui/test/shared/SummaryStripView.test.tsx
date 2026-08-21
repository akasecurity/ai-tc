import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ListIcon } from '../../src/shared/icons.tsx';
import { type SummaryStatItem, SummaryStripView } from '../../src/shared/SummaryStripView.tsx';

// The strip's height is declared in two places that cannot see each other: the
// Card is `py-2.5` around one row of content, and web-ui's
// CompactStatStripSkeleton reserves that row as a fixed 50px so the page does
// not shift when the real strip replaces it. Nothing in either package can
// measure the other, so what is pinned here is (a) the two tokens that 50px is
// the sum of, and (b) the mechanism that keeps the row to one line.
//
// The case that broke it is a value carrying a space — Detections renders
// `${active} / ${detections}`. Its min-content width is one character, so
// without `whitespace-nowrap` flex shrink breaks it across lines and the Card
// grows past the height the skeleton reserved. Measured before the fix:
// "128 / 256" took the Card to 58px and "1024 / 2048" to 76px.

const SPACED_VALUE = '128 / 256';

const ITEMS: SummaryStatItem[] = [
  { icon: ListIcon, value: SPACED_VALUE, label: 'Active', tone: 'ok' },
  { icon: ListIcon, value: 12, label: 'Rules', tone: 'violet' },
];

/** The class list of the single tag containing `text`, as a text node. */
function tagOf(html: string, text: string): string {
  const at = html.indexOf(`>${text}<`);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<', at);
  return html.slice(open, at + 1);
}

/** The whole opening tag carrying `attr`. */
function tagWithAttr(html: string, attr: string): string {
  const at = html.indexOf(attr);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<', at);
  return html.slice(open, html.indexOf('>', at) + 1);
}

function count(html: string, needle: string): number {
  return html.split(needle).length - 1;
}

const STAT = 'data-slot="summary-stat"';
const SKELETON = 'data-slot="skeleton"';

function render(props: Partial<Parameters<typeof SummaryStripView>[0]> = {}): string {
  return renderToStaticMarkup(
    <SummaryStripView items={ITEMS} isLoading={false} error={null} {...props} />,
  );
}

describe('SummaryStripView', () => {
  it('holds a spaced value on one line and lets the label absorb the shrink', () => {
    const html = render();

    // The value is the half that must neither wrap nor shrink...
    const value = tagOf(html, SPACED_VALUE);
    expect(value).toContain('whitespace-nowrap');
    expect(value).toContain('shrink-0');
    // ...and the label is the half that gives way, with the pair's `title`
    // carrying the full text once it does.
    expect(tagOf(html, 'Active')).toContain('truncate');
    expect(html).toContain(`title="${SPACED_VALUE} Active"`);
  });

  it('clips an over-wide value to its own cell rather than the next one', () => {
    // The value does not shrink, so the only thing standing between a long value
    // and the neighbouring cell's icon is a clip on the pair that holds it.
    // Without this the overflow is painted, not contained.
    const pair = tagWithAttr(render(), 'title=');
    expect(pair).toContain('items-baseline');
    expect(pair).toContain('overflow-hidden');
  });

  it('pins the two tokens web-ui derives its 50px reservation from', () => {
    // CompactStatStripSkeleton reserves `h-12.5` = 1px border + py-2.5 + a
    // size-7 icon tile + py-2.5 + 1px border. Changing either token here moves
    // the real strip and leaves that reservation behind, reintroducing the
    // shift-on-reveal this pair exists to prevent.
    // Anchored to the elements that carry them, like every other assertion in
    // this file: unanchored, an unrelated element gaining either token later
    // keeps this green while the Card it is meant to be measuring has moved.
    const html = render();
    expect(tagWithAttr(html, 'data-slot="card"')).toContain('py-2.5');
    expect(tagWithAttr(html, 'data-slot="summary-stat-icon"')).toContain('size-7');
  });

  it('withholds only the value while loading, keeping every label and icon', () => {
    const html = render({ isLoading: true });

    // The cells are still there and still say WHAT is loading — the regression
    // is a row of anonymous grey bars that named nothing.
    expect(count(html, STAT)).toBe(ITEMS.length);
    expect(html).toContain('Active');
    expect(html).toContain('Rules');
    expect(html).toContain('aria-busy="true"');
    // One value placeholder per stat, and no settled value anywhere.
    expect(count(html, SKELETON)).toBe(ITEMS.length);
    expect(html).not.toContain(SPACED_VALUE);
  });

  it('draws the same cell count loading and settled', () => {
    // The two branches render the same items, so the strip cannot change its
    // cell count — or its width-per-cell — on reveal.
    expect(count(render({ isLoading: true }), STAT)).toBe(count(render(), STAT));
  });

  it('renders the error alone, with no cells behind it', () => {
    const html = render({ error: 'nope' });
    expect(html).toContain('nope');
    expect(count(html, STAT)).toBe(0);
  });
});
