// Node environment on purpose — no DOM is needed, and under the jsdom docblock
// its sibling suite carries, `import.meta.url` resolves against the jsdom
// document (an http: URL) rather than the file, so `readFileSync` cannot take
// it. The values are read from theme.css itself: a literal restated here would
// be true by construction and would move with nothing.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

/** WCAG 2.x relative luminance, then the ratio built from it. */
function contrast(fg: string, bg: string): number {
  const luminance = (hex: string): number => {
    const [r, g, b] = [1, 3, 5].map((i) => {
      const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    }) as [number, number, number];
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const [hi, lo] = [luminance(fg), luminance(bg)].sort((a, b) => b - a) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const THEME_CSS = readFileSync(
  new URL('../../../ui-kit/src/styles/theme.css', import.meta.url),
  'utf8',
);

// Dark is one block, opened by the `.dark, [data-theme='dark']` selector.
const DARK_AT = THEME_CSS.indexOf('[data-theme=');
const BLOCKS = {
  light: THEME_CSS.slice(0, DARK_AT),
  dark: THEME_CSS.slice(DARK_AT),
} as const;

function hexOf(block: string, token: string): string {
  const hex = new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(block)?.[1];
  // Thrown rather than asserted: a token this cannot find would otherwise
  // reach the ratio as `undefined` and be measured as black.
  if (hex === undefined) throw new Error(`${token} is not defined in this theme block`);
  return hex;
}

describe('the hidden legend entry stays legible', () => {
  it('splits theme.css into two real blocks', () => {
    // A control: if the selector is renamed, `DARK_AT` goes to -1 and `slice`
    // silently hands both halves the WHOLE file, so every case below would
    // measure light twice and still pass.
    expect(DARK_AT).toBeGreaterThan(0);
    expect(hexOf(BLOCKS.light, '--color-surface')).not.toBe(hexOf(BLOCKS.dark, '--color-surface'));
  });

  // `text-text-3` paints both the label and the trailing value of a hidden
  // entry, which stays operable — it is the control that brings the series
  // back — so WCAG 1.4.3's carve-out for an INACTIVE component does not reach
  // it and it owes 4.5:1. This is the half an `opacity` guard cannot see: an
  // alpha composite is applied in the class list, never in the CSS.
  it.each(Object.entries(BLOCKS))('clears 4.5:1 against the card in %s', (theme, block) => {
    const ratio = contrast(hexOf(block, '--color-text-3'), hexOf(block, '--color-surface'));

    expect(ratio, `text-3 on surface is ${ratio.toFixed(2)}:1 in ${theme}`).toBeGreaterThanOrEqual(
      4.5,
    );
  });

  it('computes a ratio the way WCAG does', () => {
    // The control for the two cases above: a `contrast` returning a large
    // constant would pass them for any token at all.
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 1);
    expect(contrast('#ffffff', '#ffffff')).toBeCloseTo(1, 1);
    // The value this replaced: light `text-3` composited over the card at the
    // 0.55 alpha that shipped, which is the number that failed.
    expect(contrast('#b6b9bf', '#ffffff')).toBeLessThan(2.5);
  });
});
