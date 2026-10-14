/**
 * Shared number formatters used across the dashboard views.
 *
 * {@link formatNumber} takes the locale as a REQUIRED argument, and that is what
 * makes it safe in a `'use client'` component. A client component renders twice
 * — once on the server, once when the browser hydrates — and `toLocaleString()`
 * reads the renderer's OWN locale, so a Node host on en-US emits `6,456` where a
 * de-DE browser hydrates `6.456`. Passing an instant reconciles a clock and does
 * nothing for this. One explicit locale, resolved once per request and passed
 * down as a prop (see `lib/locale.ts`), renders the same string in both places
 * AND renders it in the reader's convention rather than the server's.
 */
import { DEFAULT_LOCALE } from './locale.ts';

/**
 * One formatter per locale. Built lazily because a page uses one or two, and
 * capped because the key comes from a request header — `resolveLocale` already
 * reduces it to a supported base name, and the cap is the backstop.
 */
const MAX_CACHED_LOCALES = 32;
const formatters = new Map<string, Intl.NumberFormat>();

function formatterFor(locale: string): Intl.NumberFormat {
  let formatter = formatters.get(locale);
  if (formatter === undefined) {
    if (formatters.size >= MAX_CACHED_LOCALES) formatters.clear();
    formatter = build(locale);
    formatters.set(locale, formatter);
  }
  return formatter;
}

/**
 * A formatter for `locale`, or for {@link DEFAULT_LOCALE} when `locale` is not a
 * well-formed tag. Intl throws a RangeError on one (`''`, `'en_US'`), and a host
 * that passed a locale it did not get from `resolveLocale` would otherwise take
 * the whole view down; the fallback is deterministic, so the server render and
 * the hydration still agree.
 */
function build(locale: string): Intl.NumberFormat {
  try {
    return new Intl.NumberFormat(locale);
  } catch {
    return new Intl.NumberFormat(DEFAULT_LOCALE);
  }
}

/** An exact count in the reader's convention: `1,234` (en-US) · `1.234` (de-DE). */
export function formatNumber(value: number, locale: string): string {
  return formatterFor(locale).format(value);
}

/**
 * Compact notation is PINNED to en-US rather than following the reader. Its
 * K/M/B/T roll-up is a product-wide convention shared with the CLI and the
 * plugins, the lowercasing below relies on the suffix being a Latin letter, and
 * other locales' compact forms differ far more than their separators do (de-DE
 * writes `1,2 Mio.`, en-IN rolls up in lakh and crore). A pinned locale is just
 * as hydration-safe as a passed one: both renders produce the same string.
 */
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
 * `title` built from {@link formatNumber} is what the findings location list
 * uses.
 */
export function compactCount(value: number): string {
  return compactFormat.format(value).toLowerCase();
}
