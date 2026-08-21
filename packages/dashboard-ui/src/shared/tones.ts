/**
 * The package's tonal registry: one family name → the ink/fill pair it means.
 *
 * There is one registry rather than two because the two forms a caller needs —
 * Tailwind classes and `var()` strings for an inline style — are the same
 * tokens spelled differently, and spelling them separately let them disagree:
 * `gray` carried `surface-2` in one and `surface-3` in the other, and re-toning
 * a family was two edits in two files with nothing relating them.
 *
 * The CLASS form is the source of truth and the `var()` form is derived from
 * it, not the reverse. That direction is deliberate: Tailwind only emits classes
 * it can read literally in source, so the class pairs have to be written out
 * whole and cannot be built from a token name — while `var(--color-…)` is an
 * ordinary string the compiler never has to see. Deriving the other way would
 * mean neither form was literal.
 *
 * It also decides which half the lint can police. A bare hue reached through
 * `text-*` is banned by `tonalInkTokens`, but that rule reads class literals and
 * structurally cannot see a `var()` — so keeping the classes primary puts every
 * family under the ban, and the derived `var()`s inherit whatever they say.
 */
export type Tone = 'gray' | 'orange' | 'primary' | 'red' | 'violet' | 'teal' | 'green' | 'blue';

/**
 * Written out whole, never assembled: Tailwind scans source text for complete
 * class names, so a pair built from a family name emits no rule at all.
 */
export const TONE_CLASSES: Record<Tone, { text: string; fill: string }> = {
  primary: { text: 'text-primary', fill: 'bg-primary-tint' },
  teal: { text: 'text-teal-ink', fill: 'bg-teal-fill' },
  green: { text: 'text-ok-ink', fill: 'bg-ok-fill' },
  red: { text: 'text-sev-critical-ink', fill: 'bg-sev-critical-fill' },
  orange: { text: 'text-sev-high-ink', fill: 'bg-sev-high-fill' },
  gray: { text: 'text-text-2', fill: 'bg-surface-3' },
  blue: { text: 'text-sev-low-ink', fill: 'bg-sev-low-fill' },
  violet: { text: 'text-violet-ink', fill: 'bg-violet-fill' },
};

/** `text-violet-ink` → `var(--color-violet-ink)`. */
function cssVar(utility: string): string {
  return `var(--color-${utility.replace(/^(?:text|bg)-/, '')})`;
}

/** Maps a semantic tone to a [foreground, background] pair of theme-token CSS vars. */
export function toneColors(tone: Tone): [string, string] {
  const { text, fill } = TONE_CLASSES[tone];
  return [cssVar(text), cssVar(fill)];
}
