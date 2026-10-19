import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { TRUST } from '../../src/inventory/data.ts';

// TRUST.iconBg fills the selected check circle in RadioCardList, under a glyph
// rendered in `text-on-accent`, so it must be a tonal INK rather than a hue.
const INK = /^bg-(?:ok|sev-critical|sev-high|sev-medium|sev-low|teal|violet)-ink$/;

describe('TRUST.iconBg — ink only', () => {
  it.each(Object.keys(TRUST) as (keyof typeof TRUST)[])('%s uses an ink', (level) => {
    expect(TRUST[level].iconBg).toMatch(INK);
  });
});

describe('the consumers still read the field these assertions are about', () => {
  const read = (rel: string) =>
    readFileSync(fileURLToPath(new URL(`../../src/inventory/${rel}`, import.meta.url)), 'utf8');

  it('AssetDetail feeds the check circle from .iconBg', () => {
    expect(read('AssetDetail.tsx')).toMatch(/accentOf=\{\(t\) => t\.iconBg\}/);
  });

  it('the check circle still renders its glyph in text-on-accent', () => {
    expect(read('chips.tsx')).toContain("cn('border-current text-on-accent', accentOf(m))");
  });
});
