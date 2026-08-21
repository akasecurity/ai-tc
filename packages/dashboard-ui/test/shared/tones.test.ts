import { describe, expect, it } from 'vitest';

import { type Tone, TONE_CLASSES, toneColors } from '../../src/shared/tones.ts';

// This package had two tone→(ink, fill) registries — one of Tailwind classes and
// one of `var()` strings — and they disagreed: `gray` meant `surface-2` in one
// and `surface-3` in the other, so re-toning a family was two edits in two files
// with nothing relating them. There is one registry now and the `var()` form is
// derived from the class form. What is pinned here is that it STAYS derived: a
// hand-written second map is exactly what this replaced, and it would read as
// perfectly reasonable code.

const FAMILIES: Record<Tone, [text: string, fill: string]> = {
  primary: ['text-primary', 'bg-primary-tint'],
  teal: ['text-teal-ink', 'bg-teal-fill'],
  green: ['text-ok-ink', 'bg-ok-fill'],
  red: ['text-sev-critical-ink', 'bg-sev-critical-fill'],
  orange: ['text-sev-high-ink', 'bg-sev-high-fill'],
  gray: ['text-text-2', 'bg-surface-3'],
  blue: ['text-sev-low-ink', 'bg-sev-low-fill'],
  violet: ['text-violet-ink', 'bg-violet-fill'],
};

const TONES = Object.keys(FAMILIES) as Tone[];

describe('the tonal registry', () => {
  it('covers every family exactly, with no extras', () => {
    // `Record<Tone, …>` already forces a new family to be given a pair, but it
    // cannot see a family REMOVED from the union along with its row.
    expect(Object.keys(TONE_CLASSES).sort()).toEqual(TONES.sort());
  });

  for (const tone of TONES) {
    describe(tone, () => {
      const [text, fill] = FAMILIES[tone];

      it('carries the pair it is expected to', () => {
        expect(TONE_CLASSES[tone]).toEqual({ text, fill });
      });

      it('derives its var() pair from that same pair', () => {
        // The property, not the implementation: whatever the classes say, the
        // vars name the same two tokens. A second hand-written map fails here
        // the moment it drifts — which is the only moment it matters.
        const token = (utility: string) => utility.replace(/^(?:text|bg)-/, '');
        expect(toneColors(tone)).toEqual([
          `var(--color-${token(TONE_CLASSES[tone].text)})`,
          `var(--color-${token(TONE_CLASSES[tone].fill)})`,
        ]);
      });

      it('spells its foreground as a class Tailwind can emit', () => {
        // Assembled classes emit no rule at all, so both halves must be whole
        // literals of the utility they belong to.
        expect(text).toMatch(/^text-[a-z0-9-]+$/);
        expect(fill).toMatch(/^bg-[a-z0-9-]+$/);
      });
    });
  }

  it('reaches a tonal foreground through its -ink token, never a bare hue', () => {
    // CLAUDE.md's tonal-token rule: a bare hue is a non-text colour and fails
    // contrast as text. `primary` is the documented inverse (it IS the ink, and
    // `primary-solid` is its fill) and `gray` is not a tonal family at all.
    for (const tone of TONES) {
      if (tone === 'primary' || tone === 'gray') continue;
      expect(FAMILIES[tone][0]).toMatch(/-ink$/);
    }
  });
});
