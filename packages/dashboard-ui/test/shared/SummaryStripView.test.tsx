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
  { icon: ListIcon, value: SPACED_VALUE, label: 'Active', tone: 'green' },
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

/** A rendered text node, as distinct from the same text inside a `title`. */
function values(html: string, text: string): number {
  return count(html, `>${text}<`);
}

const STAT = 'data-slot="summary-stat"';
const SKELETON = 'data-slot="skeleton"';

function render(props: Partial<Parameters<typeof SummaryStripView>[0]> = {}): string {
  return renderToStaticMarkup(<SummaryStripView items={ITEMS} isLoading={false} {...props} />);
}

describe('SummaryStripView', () => {
  it('holds a spaced value on one line and lets the label absorb the shrink', () => {
    const html = render();

    // The value never wraps — `truncate` carries `white-space: nowrap` — and it
    // ellipsizes rather than being cut mid-number if it ever has to give way.
    const value = tagOf(html, SPACED_VALUE);
    expect(value).toContain('truncate');
    expect(value).toContain('min-w-0');
    // The label is the half that gives way FIRST, and that order is the shrink
    // weight rather than a `shrink-0` on the value: without it the two shrink
    // in proportion and the number ellipsizes while the label still has room.
    const label = tagOf(html, 'Active');
    expect(label).toContain('truncate');
    expect(label).toContain('shrink-[9999]');
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
    // Anchoring catches the token MOVING or being retyped; it cannot catch one
    // being ADDED. Vertical padding on the row inside the Card takes the box to
    // 1 + 10 + (10 + 28 + 10) + 10 + 1 = 70px against a skeleton still
    // reserving 50 — the same shift, reached without touching either token.
    expect(tagWithAttr(html, STAT)).not.toMatch(/\bp[ytb]-/);
  });

  it('withholds only the value while loading, keeping every label and icon', () => {
    const html = render({ isLoading: true });

    // The cells are still there and still say WHAT is loading — the regression
    // is a row of anonymous grey bars that named nothing.
    expect(count(html, STAT)).toBe(ITEMS.length);
    // Matched as text nodes: every label is ALSO spelled into the pair's `title`,
    // so a bare `toContain` is satisfied by the attribute and stays green while
    // the visible span renders nothing — the regression this test is for.
    expect(values(html, 'Active')).toBe(1);
    expect(values(html, 'Rules')).toBe(1);
    expect(html).toContain('aria-busy="true"');
    // One value placeholder per stat, and no settled value anywhere.
    expect(count(html, SKELETON)).toBe(ITEMS.length);
    expect(html).not.toContain(SPACED_VALUE);
  });

  it('draws the same cell count loading and settled', () => {
    // The two branches render the same items, so the strip cannot change its
    // cell count — or its width-per-cell — on reveal. Scoped to the cells: the
    // fixed-width value placeholder still moves the label's truncation point
    // inside one.
    expect(count(render({ isLoading: true }), STAT)).toBe(count(render(), STAT));
  });
});
