import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ACCESS, ACCESS_ORDER, TRUST } from '../../src/inventory/data.ts';

// ACCESS carries the hue/ink split as two fields, and the reason is not obvious from
// either name — so it is pinned here rather than left to a comment.
//
//   bar    → AccessBar's stacked segments (chips.tsx) and the status dots beside
//            them (ProjectPane.tsx). Non-text marks. HUE, so they stay tellable apart.
//   accent → the selected check circle in RadioCardList, rendered as
//            `cn('border-current text-on-accent', accentOf(m))` — a solid fill under
//            a glyph. INK, so the glyph is legible on it.
//
// Collapsing both onto the ink is what shipped before, and it is exactly the failure
// the token split exists to prevent: it took AccessBar's adjacent-segment separation
// in light from 2.46/1.63/1.51 down to 1.33/1.29/1.03. The lint guard cannot see this
// one — it bans `text-*` and these are `bg-*` — so this suite is the only thing
// holding it.

const HUE = /^bg-(?:ok|sev-critical|sev-high|sev-medium|sev-low|teal|violet|primary)$/;
const INK = /^bg-(?:ok|sev-critical|sev-high|sev-medium|sev-low|teal|violet)-ink$/;

describe('ACCESS.bar — the non-text half', () => {
  it.each(ACCESS_ORDER)('%s uses a hue, never an -ink', (level) => {
    const { bar } = ACCESS[level];
    expect(bar, `ACCESS.${level}.bar`).toMatch(HUE);
    expect(bar, `ACCESS.${level}.bar must not be an ink — it paints bar segments`).not.toMatch(
      /-ink$/,
    );
  });

  // The regression was asymmetric: `approved` kept its hue while the two either side
  // moved to ink, so the bar rendered as two inks and a hue. Whatever the values are,
  // all three segments have to sit in the same half of the split.
  it('draws every segment from the same half, so the bar is not mixed', () => {
    const kinds = ACCESS_ORDER.map((level) => (ACCESS[level].bar.endsWith('-ink') ? 'ink' : 'hue'));
    expect(new Set(kinds).size, `AccessBar segments are mixed: ${kinds.join('/')}`).toBe(1);
  });
});

describe('ACCESS.accent — the fill-under-text half', () => {
  it.each(ACCESS_ORDER)('%s is dark enough to carry a glyph', (level) => {
    const { accent } = ACCESS[level];
    // primary is the inverted pair: the bare token IS the ink, so it is admissible
    // here where a tonal family's bare hue would not be.
    expect(accent, `ACCESS.${level}.accent`).toMatch(
      new RegExp(`${INK.source.slice(1, -1)}|^bg-primary$`),
    );
  });

  it('is a distinct field from bar wherever the two roles actually differ', () => {
    // Only `approved` may legitimately share a value, because primary has no separate
    // hue. If the other two ever collapse, the split has been undone.
    expect(ACCESS.open.accent).not.toBe(ACCESS.open.bar);
    expect(ACCESS.blocked.accent).not.toBe(ACCESS.blocked.bar);
  });
});

describe('TRUST.iconBg — ink only, and correctly so', () => {
  // TRUST feeds `accentOf` and nothing else (AssetDetail.tsx), so it needs no hue
  // half. Asserted so a future "make TRUST match ACCESS" change has to think.
  it.each(Object.keys(TRUST) as (keyof typeof TRUST)[])('%s uses an ink', (level) => {
    expect(TRUST[level].iconBg).toMatch(INK);
  });

  it('has no bar field to get wrong', () => {
    expect(Object.values(TRUST).every((t) => !('bar' in t))).toBe(true);
  });
});

// The field-level assertions above are only worth their green if the components still
// read the field they are named for. These read the source rather than render it —
// dashboard-ui's suite is not wired for DOM rendering of these views, and the binding
// is what breaks, not the markup.
describe('the consumers still read the field these assertions are about', () => {
  const read = (rel: string) =>
    readFileSync(fileURLToPath(new URL(`../../src/inventory/${rel}`, import.meta.url)), 'utf8');

  it('AccessBar paints segments from .bar', () => {
    expect(read('chips.tsx')).toContain('ACCESS[k].bar');
  });

  it('ProjectPane draws its status dot from .bar', () => {
    expect(read('ProjectPane.tsx')).toMatch(/rounded-sm', ACCESS\[k]\.bar/);
  });

  it('FileDetailDrawer feeds the check circle from .accent, not .bar', () => {
    const source = read('FileDetailDrawer.tsx');
    expect(source).toMatch(/accentOf=\{\(a\) => a\.accent\}/);
    expect(source, 'the check circle must not be back on the hue').not.toMatch(
      /accentOf=\{\(a\) => a\.bar\}/,
    );
  });

  it('the check circle still renders its glyph in text-on-accent', () => {
    // If this stops being true, `accent` no longer needs to be the ink and this whole
    // split should be revisited rather than silently kept.
    expect(read('chips.tsx')).toContain("cn('border-current text-on-accent', accentOf(m))");
  });
});
