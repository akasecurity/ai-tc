import type { PolicyStatsResponse } from '@akasecurity/schema';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import { PolicyStatsView } from '../../src/policies/PoliciesView.tsx';

// Static-render coverage for the Policies stat strip (this package's test
// environment is node, with no DOM). Everything here is decided at render time,
// so the whole contract is readable in the markup.
//
// What is pinned is the three-way split between the states, because two of them
// look alike and mean opposite things: a dash is a SETTLED answer the store
// could not supply, and a placeholder is "not known yet". Collapsing the
// loading branch into the settled one — passing the values through
// unconditionally — renders a row of dashes while the read is still in flight,
// which reads as a machine governing nothing.
//
// The states are told apart by ui-kit's own `data-slot` stamps rather than by
// Tailwind class substrings: a utility class is shared with whatever else
// happens to use it, so a count over one silently survives a cell that stopped
// rendering while something else gained the class.

const STATS: PolicyStatsResponse = {
  policies: 5,
  builtin: 5,
  custom: 0,
  detectionsGoverned: 7,
};

const STAT = 'data-slot="summary-stat"';
const SKELETON = 'data-slot="skeleton"';
const LABELS = ['Policies', 'Built-in', 'Custom scripts', 'Detections governed'];

function count(html: string, needle: string): number {
  return html.split(needle).length - 1;
}

/**
 * A rendered VALUE, matched as a text node. Every value is also spelled into
 * the cell's `title` (the hover fallback for a truncated label), so counting
 * raw occurrences double-counts each one.
 */
function values(html: string, text: string): number {
  return count(html, `>${text}<`);
}

describe('PolicyStatsView', () => {
  it('renders every stat against its label once settled', () => {
    const html = renderToStaticMarkup(<PolicyStatsView stats={STATS} />);

    // The positive control: without it the absence assertions below would hold
    // just as well on markup that rendered nothing at all.
    expect(count(html, STAT)).toBe(4);
    for (const label of LABELS) expect(html).toContain(label);
    // `custom` is 0 — a real answer, and the one a truthiness check would drop.
    expect(values(html, '0')).toBe(1);
    expect(values(html, '7')).toBe(1);
    expect(values(html, '—')).toBe(0);
    expect(count(html, SKELETON)).toBe(0);
  });

  it('renders a dash per stat the store could not answer', () => {
    const html = renderToStaticMarkup(<PolicyStatsView stats={null} />);

    expect(count(html, STAT)).toBe(4);
    expect(values(html, '—')).toBe(4);
    // Settled, not loading: the labels are still there to say WHAT is unknown.
    expect(html).toContain('Detections governed');
    expect(count(html, SKELETON)).toBe(0);
  });

  it('withholds only the values while loading, keeping every label', () => {
    const html = renderToStaticMarkup(<PolicyStatsView stats={undefined} loading />);

    // A dash here would be the regression: it claims a settled answer of
    // nothing for a read that has not come back.
    expect(values(html, '—')).toBe(0);
    expect(html).toContain('aria-busy="true"');
    // ...but the labels and their icons stay, so the strip still says what is
    // loading. Withholding those too leaves four anonymous grey bars.
    expect(count(html, STAT)).toBe(4);
    for (const label of LABELS) expect(html).toContain(label);
    // One value placeholder per stat, derived from the same array the settled
    // row is built from, so the cells do not change width on reveal.
    expect(count(html, SKELETON)).toBe(4);
  });

  it('forwards caller-owned spacing to the strip', () => {
    // The strip carries no margin of its own; a page that wraps it in a div to
    // add one is the thing this seam exists to remove.
    expect(renderToStaticMarkup(<PolicyStatsView stats={STATS} className="mb-3" />)).toContain(
      'mb-3',
    );
  });
});
