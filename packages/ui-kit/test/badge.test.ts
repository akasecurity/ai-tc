import { describe, expect, it } from 'vitest';

import { Badge, type BadgeProps } from '../src/badge.tsx';

// Eight of the nine variants read their pair from TONE_SOFT rather than
// respelling it, so a change to the vocabulary now reaches Badge. That is the
// point — one spelling per pair — but it also means an edit in tone.ts can move
// what Badge renders without touching this file. These are the exact strings
// rather than a second reference to TONE_SOFT, which would be true by
// construction and would move with it; so such a change has to be deliberate.
//
// `outline` is the ninth and is not a pair at all — it carries a border and no
// fill, so there is no vocabulary member for it to read.
const EXPECTED: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'bg-surface-3 text-text-2',
  outline: 'border border-border text-text-2',
  critical: 'bg-sev-critical-fill text-sev-critical-ink',
  high: 'bg-sev-high-fill text-sev-high-ink',
  medium: 'bg-sev-medium-fill text-sev-medium-ink',
  low: 'bg-sev-low-fill text-sev-low-ink',
  success: 'bg-ok-fill text-ok-ink',
  teal: 'bg-teal-fill text-teal-ink',
  primary: 'bg-primary-tint text-primary',
};

/** The className Badge would render, without a DOM. */
function classOf(variant: BadgeProps['variant']): string {
  const el = Badge({ variant, children: null }) as { props: { className: string } };
  return el.props.className;
}

describe('Badge renders each variant unchanged', () => {
  it.each(Object.entries(EXPECTED))('%s carries exactly its pair', (variant, pair) => {
    const rendered = classOf(variant as BadgeProps['variant']);

    for (const cls of pair.split(' ')) expect(rendered.split(' ')).toContain(cls);
  });

  it('keeps the shared base classes on every variant', () => {
    for (const variant of Object.keys(EXPECTED) as NonNullable<BadgeProps['variant']>[]) {
      expect(classOf(variant)).toContain('rounded-full');
    }
  });

  // Without this the suite would pass on a Badge that emitted every class at
  // once, which is the shape a broken cva config actually produces.
  it('does not leak another variant onto a variant', () => {
    expect(classOf('success').split(' ')).not.toContain('bg-teal-fill');
    expect(classOf('default').split(' ')).not.toContain('bg-sev-critical-fill');
  });
});
