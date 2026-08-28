import { describe, expect, it } from 'vitest';

import { type Tone, TONE_PARTS, TONE_SOFT, toneColors } from '../src/tone.ts';

// A family's pair lives in exactly one place. It used to live in two — a map of
// Tailwind classes and a map of `var()` strings — and they disagreed: one family
// meant `surface-2` in one and `surface-3` in the other, so re-toning it was two
// edits in two files with nothing relating them. What is pinned here is that the
// joined and `var()` forms STAY DERIVED. A hand-written second map is exactly what
// this replaced, and it would read as perfectly reasonable code.

const FAMILIES: Record<Tone, [fill: string, text: string]> = {
  neutral: ['bg-surface-2', 'text-text-2'],
  muted: ['bg-surface-3', 'text-text-2'],
  critical: ['bg-sev-critical-fill', 'text-sev-critical-ink'],
  high: ['bg-sev-high-fill', 'text-sev-high-ink'],
  medium: ['bg-sev-medium-fill', 'text-sev-medium-ink'],
  low: ['bg-sev-low-fill', 'text-sev-low-ink'],
  ok: ['bg-ok-fill', 'text-ok-ink'],
  teal: ['bg-teal-fill', 'text-teal-ink'],
  violet: ['bg-violet-fill', 'text-violet-ink'],
  primary: ['bg-primary-tint', 'text-primary'],
};

const TONES = Object.keys(FAMILIES) as Tone[];

// The two families whose halves name no tonal family, so the tonal-ink lint rule
// has nothing to match on them and only this file can hold their pairs.
const SURFACE_FAMILIES: Tone[] = ['neutral', 'muted'];

describe('the tonal registry', () => {
  it('covers every family exactly, with no extras', () => {
    // `Record<Tone, …>` already forces a new family to be given a pair, but it
    // cannot see a family REMOVED from the union along with its row.
    expect(Object.keys(TONE_PARTS).sort()).toEqual([...TONES].sort());
    expect(Object.keys(TONE_SOFT).sort()).toEqual([...TONES].sort());
  });

  it('keeps the two neutrals distinct', () => {
    // The whole reason `muted` exists. Collapsing these is a silent visual change:
    // in light, surface-2 equals the canvas, so a `neutral` tile is invisible on
    // the page, while `muted` is the tile that still has to read on what it sits on.
    expect(TONE_PARTS.neutral.fill).not.toBe(TONE_PARTS.muted.fill);
  });

  for (const tone of TONES) {
    describe(tone, () => {
      const [fill, text] = FAMILIES[tone];

      it('carries the pair it is expected to', () => {
        expect(TONE_PARTS[tone]).toEqual({ fill, text });
      });

      it('joins that same pair, fill first', () => {
        // The property, not the implementation. Order is load-bearing beyond
        // rendering: callers store this string and compare it, and twMerge makes
        // either order render identically — so a flip changes the value without
        // changing a pixel.
        expect(TONE_SOFT[tone]).toBe(`${TONE_PARTS[tone].fill} ${TONE_PARTS[tone].text}`);
      });

      it('derives its var() pair from that same pair', () => {
        // Whatever the classes say, the vars name the same two tokens. A second
        // hand-written map fails here the moment it drifts — the only moment it
        // matters.
        const token = (utility: string) => utility.replace(/^(?:text|bg)-/, '');
        expect(toneColors(tone)).toEqual([
          `var(--color-${token(TONE_PARTS[tone].text)})`,
          `var(--color-${token(TONE_PARTS[tone].fill)})`,
        ]);
      });

      it('spells both halves as classes Tailwind can emit', () => {
        // Assembled classes emit no rule at all, so each half must be a whole
        // literal of the utility it belongs to.
        expect(fill).toMatch(/^bg-[a-z0-9-]+$/);
        expect(text).toMatch(/^text-[a-z0-9-]+$/);
      });
    });
  }

  it('reaches a tonal foreground through its -ink token, never a bare hue', () => {
    // A bare hue is a non-text colour and fails contrast as text. `primary` is the
    // documented inverse — it IS the ink, and `primary-tint` is its fill — and the
    // two surface families are not tonal families at all.
    for (const tone of TONES) {
      if (tone === 'primary' || SURFACE_FAMILIES.includes(tone)) continue;
      expect(FAMILIES[tone][1]).toMatch(/-ink$/);
    }
  });
});
