/**
 * Shared date and time formatting, in an EXPLICIT locale.
 *
 * The same reasoning as `numberFormat.ts`: `toLocaleString()` and
 * `toLocaleTimeString([], …)` read the renderer's own locale, so a client
 * component formatted that way renders one string on the server and another
 * when the browser hydrates it. The locale here is required, and comes from the
 * one the host resolved for the request (see `lib/locale.ts`).
 *
 * The time ZONE is still the renderer's own. The dashboard answers only
 * requests addressed to a loopback host (see web-ui's middleware), so the
 * server and the browser run on one machine and read one zone; a request
 * carries no time zone to pass down, unlike its locale.
 */
import { DEFAULT_LOCALE } from './locale.ts';

const MAX_CACHED_LOCALES = 32;

/**
 * Formatters keyed by the options object, then by locale. Callers pass a
 * module-level options constant, so the outer key is stable for the life of the
 * module and nothing is rebuilt per call.
 */
const formatters = new WeakMap<Intl.DateTimeFormatOptions, Map<string, Intl.DateTimeFormat>>();

function formatterFor(locale: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  let byLocale = formatters.get(options);
  if (byLocale === undefined) {
    byLocale = new Map();
    formatters.set(options, byLocale);
  }
  let formatter = byLocale.get(locale);
  if (formatter === undefined) {
    if (byLocale.size >= MAX_CACHED_LOCALES) byLocale.clear();
    formatter = build(locale, options);
    byLocale.set(locale, formatter);
  }
  return formatter;
}

/**
 * A formatter for `locale`, or for {@link DEFAULT_LOCALE} when `locale` is not a
 * well-formed tag — see numberFormat.ts's `build` for why it falls back rather
 * than throwing. An invalid OPTION still throws, from the retry: that is a bug in
 * a module constant, not request input.
 */
function build(locale: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  try {
    return new Intl.DateTimeFormat(locale, options);
  } catch {
    return new Intl.DateTimeFormat(DEFAULT_LOCALE, options);
  }
}

/**
 * An instant (epoch milliseconds) in the reader's convention, with the fields
 * `options` names. Pass a module-level options constant, not a fresh literal per
 * call: the options object is the cache key.
 *
 * An unparseable instant (`Date.parse` of a malformed string is NaN) reads as
 * the empty string — `Intl.DateTimeFormat#format` throws a RangeError on it,
 * which would take the whole view down for one bad timestamp.
 */
export function formatDateTime(
  epochMs: number,
  locale: string,
  options: Intl.DateTimeFormatOptions,
): string {
  if (!Number.isFinite(epochMs)) return '';
  return formatterFor(locale, options).format(epochMs);
}
