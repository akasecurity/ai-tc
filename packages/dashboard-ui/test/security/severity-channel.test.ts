// Node environment on purpose, as in legend-contrast.test.ts: the hues are read
// from theme.css itself, so a literal restated here would be true by
// construction and would move with nothing.
import { readFileSync } from 'node:fs';

import type { Severity } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { SEVERITY_DASH } from '../../src/security/meta.ts';

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
  // Thrown rather than asserted: a token this cannot find would otherwise reach
  // the ratio as `undefined` and be measured as black.
  if (hex === undefined) throw new Error(`${token} is not defined in this theme block`);
  return hex;
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Every unordered pair of severities, which is what 1.4.11 is asked of. */
const PAIRS: [Severity, Severity][] = SEVERITIES.flatMap((a, i) =>
  SEVERITIES.slice(i + 1).map((b): [Severity, Severity] => [a, b]),
);

function hueRatio(block: string, a: Severity, b: Severity): number {
  return contrast(hexOf(block, `--color-sev-${a}`), hexOf(block, `--color-sev-${b}`));
}

describe('a severity series is identifiable without colour', () => {
  it('splits theme.css into two real blocks', () => {
    // A control for every case below: if the selector is renamed, `DARK_AT`
    // goes to -1 and `slice` silently hands both halves the WHOLE file, so
    // every case would measure light twice and still pass.
    expect(DARK_AT).toBeGreaterThan(0);
    expect(hexOf(BLOCKS.light, '--color-surface')).not.toBe(hexOf(BLOCKS.dark, '--color-surface'));
  });

  it('computes a ratio the way WCAG does', () => {
    // The control for the measurements below: a `contrast` returning a large
    // constant would satisfy the 3:1 arm of every pair for any hue at all.
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 1);
    expect(contrast('#ffffff', '#ffffff')).toBeCloseTo(1, 1);
  });

  it.each(PAIRS)('tells %s from %s in both themes', (a, b) => {
    // The property WCAG 2.2 1.4.11 actually asks for, stated as the disjunction
    // it is: two adjacent non-text colours must either clear 3:1 against each
    // other, OR not be the only thing separating the two series. Written this
    // way the guard survives the fix it does not mandate — re-tune the hues to
    // clear 3:1 and the dash stops being load-bearing, with this case still
    // green and still meaningful.
    for (const [theme, block] of Object.entries(BLOCKS)) {
      const ratio = hueRatio(block, a, b);
      const separated = ratio >= 3 || SEVERITY_DASH[a] !== SEVERITY_DASH[b];
      expect(
        separated,
        `${a} vs ${b} in ${theme}: hue ${ratio.toFixed(2)}:1, dash ${String(
          SEVERITY_DASH[a],
        )} vs ${String(SEVERITY_DASH[b])}`,
      ).toBe(true);
    }
  });

  it('is load-bearing, because no pair is separable by hue alone', () => {
    // Without this the case above could pass on hues that already clear 3:1,
    // never reading `SEVERITY_DASH` at all. It records the measurement the dash
    // exists to answer: 6 of 6 pairs under 3:1 in BOTH themes, worst
    // critical/low at 1.03:1 light and 1.10:1 dark.
    //
    // If this ever goes red because the palette improved, the dash is no longer
    // the only thing holding 1.4.11 up and the disjunction above can be
    // revisited — it is not a reason to loosen this number.
    for (const [theme, block] of Object.entries(BLOCKS)) {
      for (const [a, b] of PAIRS) {
        const ratio = hueRatio(block, a, b);
        expect(ratio, `${a} vs ${b} in ${theme} is ${ratio.toFixed(2)}:1`).toBeLessThan(3);
      }
    }
  });

  it('gives each severity its own pattern', () => {
    // Distinctness is what the disjunction above leans on, and `critical` is
    // deliberately the solid one, so the set is three patterns plus `undefined`.
    const patterns = SEVERITIES.map((s) => SEVERITY_DASH[s]);
    expect(new Set(patterns).size).toBe(SEVERITIES.length);
    expect(SEVERITY_DASH.critical).toBeUndefined();
  });
});
