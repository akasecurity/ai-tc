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

/** The whole opening tag carrying `attr`. */
function tagWithAttr(html: string, attr: string): string {
  const at = html.indexOf(attr);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<', at);
  return html.slice(open, html.indexOf('>', at) + 1);
}

/**
 * A rendered text node. Both the values AND the labels are also spelled into the
 * cell's `title` (the hover fallback for a truncated label), so a bare
 * `toContain` is satisfied by the attribute alone — it stays green while the
 * visible span renders nothing, which is the regression these tests exist for.
 * Matching `>text<` is what distinguishes the rendered text from the attribute.
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
    for (const label of LABELS) expect(values(html, label)).toBe(1);
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
    expect(values(html, 'Detections governed')).toBe(1);
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
    for (const label of LABELS) expect(values(html, label)).toBe(1);
    // One value placeholder per stat, derived from the same array the settled
    // row is built from, so the CELLS do not change width on reveal — the label's
    // truncation point inside one still can, since the placeholder is a fixed
    // width and the value it stands in for is not.
    expect(count(html, SKELETON)).toBe(4);
  });

  it('carries the shared gap by default, and lets a caller replace it', () => {
    // The gap under the strip is what a page and its skeleton must agree on
    // exactly, so it is a default they share rather than a literal each spells.
    // Asserting the default by PASSING it would hold whether or not the prop is
    // wired at all — so the seam is shown by an override that must win.
    const card = (html: string) => tagWithAttr(html, 'data-slot="card"');
    expect(card(renderToStaticMarkup(<PolicyStatsView stats={STATS} />))).toContain('mb-3');
    const overridden = card(
      renderToStaticMarkup(<PolicyStatsView stats={STATS} className="mb-0" />),
    );
    expect(overridden).toContain('mb-0');
    expect(overridden).not.toContain('mb-3');
  });
});
