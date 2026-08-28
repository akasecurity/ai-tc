import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { type SolidTone, type Tone, TONE_SOFT, TONE_SOLID } from '../src/tone.ts';

// `Record<Tone, string>` constrains the KEYS and says nothing about the values,
// so every way a pair can be wrong is invisible to the compiler: a `bg-ok` that
// should be `bg-ok-fill`, an ink borrowed from another family, a `-fill` where
// the ink belongs. Each of those fails the way this module exists to prevent —
// an undefined theme variable emits no utility at all, so the element inherits
// its color rather than landing on something visibly wrong, and in dark the hue
// and ink halves are equal, which hides a mistake in one theme while it ships
// broken in the other.
//
// So the values are checked against theme.css itself rather than against a
// second copy of the strings. A literal restated here would be true by
// construction and would move with nothing.

const THEME_CSS = readFileSync(new URL('../src/styles/theme.css', import.meta.url), 'utf8');

// Dark is class-activated in this file (`[data-theme='dark']`), never
// `prefers-color-scheme` — so the two themes are exactly two blocks, split at
// that selector.
const DARK_SELECTOR_AT = THEME_CSS.indexOf("[data-theme='dark']");
const LIGHT_BLOCK = THEME_CSS.slice(0, DARK_SELECTOR_AT);
const DARK_BLOCK = THEME_CSS.slice(DARK_SELECTOR_AT);

/** `bg-sev-critical-fill` / `text-ok-ink` → `--color-sev-critical-fill`. */
function tokenOf(className: string): string {
  return `--color-${className.replace(/^(?:bg|text)-/, '')}`;
}

function definesToken(block: string, token: string): boolean {
  return block.includes(`${token}:`);
}

/** The two halves of a pair, asserted to BE two halves before being read. */
function halvesOf(pair: string): { fill: string; ink: string } {
  const parts = pair.split(' ');
  expect(parts, `${pair} is not exactly a background and a foreground`).toHaveLength(2);
  const [fill, ink] = parts as [string, string];
  expect(fill, `${pair} does not lead with its background half`).toMatch(/^bg-/);
  expect(ink, `${pair} does not close with its foreground half`).toMatch(/^text-/);
  return { fill, ink };
}

describe('the tonal pairs resolve in theme.css', () => {
  // The strongest of the three: a token nothing defines generates no utility,
  // which is the silent failure. Both themes are required because a token
  // defined only in light leaves dark inheriting, and vice versa.
  it.each(Object.entries(TONE_SOFT))('TONE_SOFT.%s is defined in both themes', (_tone, pair) => {
    const { fill, ink } = halvesOf(pair);

    for (const token of [tokenOf(fill), tokenOf(ink)]) {
      expect(definesToken(LIGHT_BLOCK, token), `${token} is undefined in light`).toBe(true);
      expect(definesToken(DARK_BLOCK, token), `${token} is undefined in dark`).toBe(true);
    }
  });

  it.each(Object.entries(TONE_SOLID))('TONE_SOLID.%s is defined in both themes', (_tone, pair) => {
    const { fill, ink } = halvesOf(pair);

    for (const token of [tokenOf(fill), tokenOf(ink)]) {
      expect(definesToken(LIGHT_BLOCK, token), `${token} is undefined in light`).toBe(true);
      expect(definesToken(DARK_BLOCK, token), `${token} is undefined in dark`).toBe(true);
    }
  });

  // A control: without it, a `definesToken` that always returned true would pass
  // every case above.
  it('reports a token theme.css does not define', () => {
    expect(definesToken(LIGHT_BLOCK, '--color-not-a-family-fill')).toBe(false);
    expect(definesToken(DARK_BLOCK, '--color-not-a-family-fill')).toBe(false);
  });
});

describe('the tonal pairs are shaped as fill + ink', () => {
  // Catches the half that resolves but is the wrong half — `bg-ok` names a real
  // token (the HUE), so the resolution check above passes on it. Two families
  // are irregular and are named rather than inferred: `primary`'s bare token IS
  // the ink and its tint is `-tint`, and `neutral` is a surface rather than a
  // tonal family.
  const IRREGULAR: Partial<Record<Tone, string>> = {
    neutral: 'bg-surface-2 text-text-2',
    primary: 'bg-primary-tint text-primary',
  };

  it.each(Object.entries(TONE_SOFT))(
    'TONE_SOFT.%s pairs a -fill with its own -ink',
    (tone, pair) => {
      const irregular = IRREGULAR[tone as Tone];
      if (irregular !== undefined) {
        expect(pair).toBe(irregular);
        return;
      }

      const { fill, ink } = halvesOf(pair);
      expect(fill, `${tone}'s background half is not a -fill`).toMatch(/-fill$/);
      expect(ink, `${tone}'s foreground half is not an -ink`).toMatch(/-ink$/);

      // The family must be the SAME on both halves: `bg-ok-fill text-teal-ink`
      // satisfies every check above it.
      expect(fill.replace(/^bg-/, '').replace(/-fill$/, '')).toBe(
        ink.replace(/^text-/, '').replace(/-ink$/, ''),
      );
    },
  );

  it.each(Object.entries(TONE_SOLID))(
    'TONE_SOLID.%s fills with its ink over on-accent',
    (tone, pair) => {
      const { fill, ink } = halvesOf(pair);

      // A solid fill is the family's INK used as a background — the inverse of the
      // soft pair, which is why it cannot be derived from TONE_SOFT by suffix.
      expect(fill, `${tone}'s solid background is not its -ink`).toMatch(/-ink$/);
      expect(ink).toBe('text-on-accent');
      expect(fill.replace(/^bg-/, '')).toBe(
        TONE_SOFT[tone as SolidTone].split(' ')[1]?.replace(/^text-/, ''),
      );
    },
  );
});
