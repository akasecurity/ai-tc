/**
 * Shared en-US number formatters used across the dashboard views.
 *
 * The locale is PINNED rather than left to the runtime, and that is what makes
 * these safe in a `'use client'` component. A client component renders twice —
 * once on the server, once when the browser hydrates — and `toLocaleString()`
 * reads the renderer's OWN locale, so a Node host on en-US emits `6,456` where a
 * de-DE browser hydrates `6.456`. Passing an instant reconciles a clock and does
 * nothing for this. A fixed locale renders the same string in both places, so
 * there is no mismatch to acknowledge or suppress.
 */
export const numberFormat = new Intl.NumberFormat('en-US');

const compactFormat = new Intl.NumberFormat('en-US', { notation: 'compact' });

/**
 * The same count, short enough for a narrow column: `486` · `1.2k` · `12k` ·
 * `1.2m`.
 *
 * Lowercased, because Intl emits `1.2K` and the dashboard's terse forms are
 * lowercase (see relativeTimeShort's `2h`). Only the magnitude suffixes are
 * letters, so nothing else can be affected.
 *
 * It is LOSSY, and lossy in a way a reader cannot see: compact notation rounds
 * across its own boundary, so 9,999 reads `10k` and 999,999 reads `1m`. Anything
 * rendering this owes the exact number somewhere the reader can reach — a
 * `title` built from {@link numberFormat} is what the findings location list
 * uses.
 */
export function compactCount(value: number): string {
  return compactFormat.format(value).toLowerCase();
}
