// Node environment on purpose, as in legend-contrast.test.ts: the values are read
// from theme.css itself, so a literal restated here could not move with the theme.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { MAX_TINT_PERCENT, MIN_TINT_PERCENT, tint } from '../../src/security/heat-tint.ts';

type Rgb = [number, number, number];

function rgb(hex: string): Rgb {
  return [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16)) as Rgb;
}

/** WCAG 2.x relative luminance, then the ratio built from it. */
function contrast(a: Rgb, b: Rgb): number {
  const luminance = (c: Rgb): number => {
    const [r, g, bl] = c.map((v) => {
      const x = v / 255;
      return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
    }) as Rgb;
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
  };
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** A hue at `pct`% alpha over `base`, composited in sRGB like the browser does. */
function over(hue: Rgb, pct: number, base: Rgb): Rgb {
  const a = pct / 100;
  const mix = (h: number, b: number): number => Math.round(h * a + b * (1 - a));
  return [mix(hue[0], base[0]), mix(hue[1], base[1]), mix(hue[2], base[2])];
}

const THEME_CSS = readFileSync(
  new URL('../../../ui-kit/src/styles/theme.css', import.meta.url),
  'utf8',
);
const DARK_AT = THEME_CSS.indexOf('[data-theme=');
const BLOCKS = { light: THEME_CSS.slice(0, DARK_AT), dark: THEME_CSS.slice(DARK_AT) } as const;

function hexOf(block: string, token: string): Rgb {
  const hex = new RegExp(`${token}:\\s*(#[0-9a-fA-F]{6})`).exec(block)?.[1];
  // Thrown rather than asserted: a token not found would be measured as black.
  if (hex === undefined) throw new Error(`${token} is not defined in this theme block`);
  return rgb(hex);
}

const HUES = ['critical', 'high', 'medium', 'low'] as const;
const AA_NORMAL_TEXT = 4.5;

describe('the matrix shading keeps its text legible', () => {
  it('splits theme.css into two real blocks', () => {
    // A control: a renamed selector sends DARK_AT to -1 and hands both halves the
    // whole file, so every case below would measure light twice and still pass.
    expect(DARK_AT).toBeGreaterThan(0);
    expect(hexOf(BLOCKS.light, '--color-surface')).not.toEqual(
      hexOf(BLOCKS.dark, '--color-surface'),
    );
  });

  it.each(['light', 'dark'] as const)(
    'holds 4.5:1 for every severity hue at the tint cap in the %s theme',
    (theme) => {
      const block = BLOCKS[theme];
      const surface = hexOf(block, '--color-surface');
      const text = hexOf(block, '--color-text');
      for (const hue of HUES) {
        const ratio = contrast(
          text,
          over(hexOf(block, `--color-sev-${hue}`), MAX_TINT_PERCENT, surface),
        );
        expect(ratio, `${theme} ${hue} at ${String(MAX_TINT_PERCENT)}%`).toBeGreaterThanOrEqual(
          AA_NORMAL_TEXT,
        );
      }
    },
  );

  it('is sensitive: the old 55% cap would fail in the dark theme', () => {
    // The control that shows the assertion above can go red at all.
    const block = BLOCKS.dark;
    const surface = hexOf(block, '--color-surface');
    const text = hexOf(block, '--color-text');
    const medium = contrast(text, over(hexOf(block, '--color-sev-medium'), 55, surface));
    expect(medium).toBeLessThan(AA_NORMAL_TEXT);
  });

  it('applies the cap to the largest cell and the floor to a tiny one', () => {
    expect(tint('var(--x)', 100, 100)).toContain(` ${String(MAX_TINT_PERCENT)}%`);
    expect(tint('var(--x)', 1, 100000)).toContain(` ${String(MIN_TINT_PERCENT)}%`);
    expect(tint('var(--x)', 0, 100)).toBeUndefined();
  });
});
