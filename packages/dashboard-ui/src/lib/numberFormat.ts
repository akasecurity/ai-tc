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

/** The separator `locale` groups digits with, or null where it uses none. */
function groupSeparator(locale: string): string | null {
  const parts = formatterFor(locale).formatToParts(1_000_000);
  return parts.find((part) => part.type === 'group')?.value ?? null;
}

/** `text` with the digits `locale` writes (`٥` in ar-EG) read as ASCII. */
function toAsciiDigits(text: string, locale: string): string {
  const formatter = formatterFor(locale);
  const digits = Array.from({ length: 10 }, (_, digit) => formatter.format(digit));
  return text.replace(/\p{Nd}/gu, (char) => {
    const digit = digits.indexOf(char);
    return digit === -1 ? char : String(digit);
  });
}

/**
 * The whole number typed text names, or null when it names none. Accepts bare
 * digits, ASCII or the locale's own, and a grouped form only when it is exactly
 * what {@link formatNumber} writes for that number: `1,000` is a thousand in
 * en-US, while `1,00` and de-DE's `1.5` are refused rather than misread.
 */
export function parseCount(text: string, locale: string): number | null {
  const trimmed = text.trim();
  const ascii = toAsciiDigits(trimmed, locale);
  if (/^\d+$/.test(ascii)) return Number(ascii);
  const separator = groupSeparator(locale);
  if (separator === null) return null;
  const digits = ascii.split(separator).join('');
  // Whitespace separators (fr-FR's narrow no-break space) are typed as a plain space.
  const grouped = /^\s$/.test(separator) ? trimmed.replace(/\s/g, separator) : trimmed;
  const bare = /^\s$/.test(separator) ? digits.replace(/\s/g, '') : digits;
  if (!/^\d+$/.test(bare)) return null;
  const value = Number(bare);
  return formatNumber(value, locale) === grouped ? value : null;
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
