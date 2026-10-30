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

// Dark is one block, opened by the `.dark, [data-theme='dark']` selector. The
// anchor is that opening line and not a bare search for `[data-theme=`: the
// same selector is NAMED ten lines earlier inside the `@custom-variant dark`
// declaration, which says nothing about where the tokens sit, so splitting
// there would put the boundary in a place no token block controls — and a
// reordered variant, or a severity token added to `:root` below it, would then
// hand one theme's hexes to both halves and measure that theme twice.
const DARK_AT = /^\[data-theme='dark'\] \{/m.exec(THEME_CSS)?.index ?? -1;
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

/**
 * The legend chip and the tooltip chip, which spell their size as one shared
 * class string. Read from source for the reason the hues are: a width restated
 * here would be true by construction and would move with nothing.
 */
const CHIP_SOURCES = ['../../src/shared/SeriesLegend.tsx', '../../src/shared/charts.tsx'];

function chipWidthPx(relative: string): number {
  const src = readFileSync(new URL(relative, import.meta.url), 'utf8');
  const units = /\bh-2 w-(\d+) shrink-0 rounded-xs\b/.exec(src)?.[1];
  // Thrown rather than asserted: a chip whose class this cannot read would
  // otherwise come back NaN, and every comparison against NaN is false — the
  // case below would report nothing at all.
  if (units === undefined) throw new Error(`no series chip class found in ${relative}`);
  // Tailwind's spacing unit is 0.25rem, which is 4px at the default root size.
  return Number(units) * 4;
}

/**
 * The pixel length of one full repeat of a dasharray. SVG repeats an
 * odd-length array twice before it closes, so `5` is a 10px cycle and not a
 * 5px one.
 */
function cycleOf(dash: string): number {
  const lengths = dash
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number);
  const sum = lengths.reduce((total, n) => total + n, 0);
  return lengths.length % 2 === 0 ? sum : sum * 2;
}

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
    // And the boundary is the token block's OWN opening line. The same selector
    // is named earlier, inside `@custom-variant dark (…)`, and a boundary that
    // landed there would still leave two plausible halves — every severity hex
    // happens to fall on the correct side of it today — so what has to be
    // pinned is the boundary's shape rather than the hexes either side of it: a
    // line start, and a line that is the block's opening and nothing else.
    // Both go red on a bare `indexOf('[data-theme=')`, which lands mid-line
    // inside that declaration; asserting which half holds the declaration does
    // NOT, because the split falls after the `@custom-variant` text itself.
    expect(THEME_CSS[DARK_AT - 1]).toBe('\n');
    expect(BLOCKS.dark.split('\n')[0]).toBe("[data-theme='dark'] {");
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

  it('keeps every pattern inside the width of the chip that redraws it', () => {
    // The legend and the tooltip redraw a line's dash as a small chip, and a
    // cycle wider than the chip is clipped: the chip shows a prefix of the
    // pattern and silently drops the rest, which is how `11 3 2 3` lost its
    // trailing gap on a 16px chip and stopped reading as the same rhythm as
    // its line. Both chips are the same element spelled in two files, so the
    // width is read from the source rather than restated here.
    //
    // A control for the measurement itself: SVG closes an odd-length array by
    // repeating it, so `9 3 2` is a 28px cycle and not a 14px one. Measured as
    // 14 it would slip under a 16px chip that in fact clips it.
    expect(cycleOf('9 3 2')).toBe(28);
    expect(cycleOf('9 3 2 2')).toBe(16);
    const widths = CHIP_SOURCES.map(chipWidthPx);
    expect(new Set(widths).size, `the two chips disagree on width: ${widths.join(' vs ')}`).toBe(1);
    const [chip] = widths as [number];
    for (const severity of SEVERITIES) {
      const dash = SEVERITY_DASH[severity];
      if (dash === undefined) continue;
      expect(
        cycleOf(dash),
        `${severity} draws a ${dash} cycle on a ${String(chip)}px chip`,
      ).toBeLessThanOrEqual(chip);
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
