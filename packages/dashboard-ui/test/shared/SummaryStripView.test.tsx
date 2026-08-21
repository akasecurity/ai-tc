import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { ListIcon } from '../../src/shared/icons.tsx';
import { type SummaryStatItem, SummaryStripView } from '../../src/shared/SummaryStripView.tsx';

// The strip's height is declared in two places that cannot see each other: the
// Card is `py-2.5` around one row of content, and web-ui's
// CompactStatStripSkeleton reserves that row as a fixed 50px so the page does
// not shift when the real strip replaces it. Nothing in either package can
// measure the other, so what is pinned here is the mechanism that keeps the row
// to one line.
//
// The case that broke it is a value carrying a space — Detections renders
// `${active} / ${detections}`. Its min-content width is one character, so
// without `whitespace-nowrap` flex shrink breaks it across lines and the Card
// grows past the height the skeleton reserved. Measured before the fix:
// "128 / 256" took the Card to 58px and "1024 / 2048" to 76px.

const SPACED_VALUE = '128 / 256';

const ITEMS: SummaryStatItem[] = [
  {
    icon: ListIcon,
    value: SPACED_VALUE,
    label: 'Active',
    text: 'text-ok-ink',
    fill: 'bg-ok-fill',
  },
];

/** The class list of the single tag containing `text`, as a text node. */
function tagOf(html: string, text: string): string {
  const at = html.indexOf(`>${text}<`);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<', at);
  return html.slice(open, at + 1);
}

describe('SummaryStripView', () => {
  it('holds a spaced value on one line and lets the label absorb the shrink', () => {
    const html = renderToStaticMarkup(
      <SummaryStripView items={ITEMS} isLoading={false} error={null} />,
    );

    // The value is the half that must not wrap...
    expect(tagOf(html, SPACED_VALUE)).toContain('whitespace-nowrap');
    // ...and the label is the half that gives way, with the pair's `title`
    // carrying the full text once it does.
    expect(tagOf(html, 'Active')).toContain('truncate');
    expect(html).toContain(`title="${SPACED_VALUE} Active"`);
  });
});
