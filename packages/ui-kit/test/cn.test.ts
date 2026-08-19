import { describe, expect, it } from 'vitest';

import { cn } from '../src/lib/cn.ts';

// `cn` is the one piece of this package that is logic rather than markup, and
// the only part a non-rendering suite can say anything true about. Everything
// else here is a Radix primitive plus classes, which needs a renderer tier.
//
// The case worth pinning is the `extendTailwindMerge` registration in cn.ts.
// `text-ui` and `text-label` are custom FONT-SIZE utilities defined in
// theme.css, but tailwind-merge classifies an unknown `text-*` as a COLOR — so
// without that registration it treats `text-ui` and `text-text-2` as the same
// group and drops the earlier one. The failure is silent: the class list still
// renders, the type checks, nothing throws, and the text quietly comes out at
// the wrong size. Deleting the `extend` block is the mutation these cases exist
// to catch.
describe('cn', () => {
  it('keeps a custom font-size utility alongside a color utility', () => {
    // The whole point of the extend block: these are DIFFERENT groups, so both
    // survive. Classified as one group, the later class wins and `text-ui` is
    // gone.
    const merged = cn('text-ui', 'text-text-2');

    expect(merged).toContain('text-ui');
    expect(merged).toContain('text-text-2');
  });

  it('keeps text-label alongside a tonal ink color', () => {
    // The `-ink` spelling is the one CLAUDE.md requires for a foreground on a
    // tonal tint, so it is the pairing that actually ships.
    const merged = cn('text-label', 'text-sev-critical-ink');

    expect(merged).toContain('text-label');
    expect(merged).toContain('text-sev-critical-ink');
  });

  it('still resolves a genuine conflict last-wins', () => {
    // The positive control. Without it, a `cn` rewritten to concatenate blindly
    // would satisfy both cases above — they only assert that things SURVIVE.
    expect(cn('text-text-1', 'text-text-2')).toBe('text-text-2');
    expect(cn('p-2', 'p-4')).toBe('p-4');
  });

  it('applies clsx conditional semantics', () => {
    // The flags come from a value rather than a literal: `false && 'b'` written
    // inline is a constant expression the linter rejects, and it would also test
    // constant folding rather than what `cn` does with a falsy argument.
    const off = Math.min(0, 1) === 1;

    expect(cn('a', off && 'b', undefined, ['c', { d: true, e: off }])).toBe('a c d');
  });
});
