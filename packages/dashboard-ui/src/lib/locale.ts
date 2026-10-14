/**
 * The one locale a page formats its numbers and times in.
 *
 * A `'use client'` component renders twice — once on the server, once when the
 * browser hydrates it — and an argument-less `toLocaleString()` reads each
 * renderer's OWN locale. On a machine whose Node process runs under en-US and
 * whose browser is set to de-DE, the server emits `6,456` and the browser
 * hydrates `6.456`, and React throws the server HTML for that subtree away. A
 * server component has the opposite problem: it renders once, but in the Node
 * process's locale, which is not the reader's.
 *
 * So the host resolves ONE locale per request, from the request's
 * `Accept-Language` header, and hands it down as a prop exactly like
 * `renderedAt`. Every shared formatter takes it as a REQUIRED argument, so both
 * renders use the same explicit locale and a call site that forgets one fails
 * to compile.
 *
 * This decides the format CONVENTIONS — digit grouping, the decimal mark, the
 * order of a date's fields, a 12- or 24-hour clock. It does not translate the
 * dashboard: its copy is English, and so are the words its relative-time and
 * day-heading helpers produce.
 */

/** The locale used when a request names none this runtime can format. */
export const DEFAULT_LOCALE = 'en-US';

/**
 * How much of a header is read. A real browser sends a handful of entries; the
 * bound keeps a hostile header from turning one page render into thousands of
 * locale lookups.
 */
const MAX_HEADER_LENGTH = 1024;
const MAX_ENTRIES = 32;

const QVALUE = /^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/;

interface Weighted {
  tag: string;
  q: number;
  order: number;
}

function parseEntries(header: string): Weighted[] {
  const entries: Weighted[] = [];
  const parts = header.slice(0, MAX_HEADER_LENGTH).split(',').slice(0, MAX_ENTRIES);
  parts.forEach((part, order) => {
    const [rawTag = '', ...params] = part.split(';');
    const tag = rawTag.trim();
    if (tag === '' || tag === '*') return;
    let q = 1;
    for (const param of params) {
      const match = /^\s*q\s*=\s*(.*?)\s*$/i.exec(param);
      if (match?.[1] === undefined) continue;
      // RFC 9110's qvalue: 0 to 1 with at most three decimals. Anything else is
      // not a weight, and the entry it qualifies is not a choice.
      q = QVALUE.test(match[1]) ? Number(match[1]) : Number.NaN;
    }
    if (!(q > 0)) return;
    entries.push({ tag, q, order });
  });
  // Highest weight first; equal weights keep the order the header gave them.
  return entries.sort((a, b) => b.q - a.q || a.order - b.order);
}

/**
 * The canonical form of a tag this runtime can format numbers AND dates in, or
 * null when it cannot.
 *
 * Reduced to the base name (language, script, region): a browser sends no
 * Unicode extensions, so dropping them loses nothing and keeps them out of the
 * formatter caches' keys. It does NOT make the key space small — `lookup`
 * accepts any well-formed region over a supported language (`de-ZZ` formats as
 * `de`) — which is why those caches carry a size cap of their own.
 */
function supported(tag: string): string | null {
  let canonical: string;
  try {
    const [first] = Intl.getCanonicalLocales(tag);
    if (first === undefined) return null;
    canonical = new Intl.Locale(first).baseName;
  } catch {
    // A malformed tag is a RangeError here, and is simply not a choice.
    return null;
  }
  const options = { localeMatcher: 'lookup' } as const;
  const numbers = Intl.NumberFormat.supportedLocalesOf([canonical], options);
  const dates = Intl.DateTimeFormat.supportedLocalesOf([canonical], options);
  return numbers.length > 0 && dates.length > 0 ? canonical : null;
}

/**
 * The reader's locale, from an `Accept-Language` header value: the
 * highest-weighted tag this runtime can format, else {@link DEFAULT_LOCALE}.
 *
 * Total — an absent, empty, malformed or wholly unsupported header resolves to
 * the default rather than throwing, because a page must render whatever the
 * request carried.
 */
export function resolveLocale(acceptLanguage: string | null | undefined): string {
  if (!acceptLanguage) return DEFAULT_LOCALE;
  for (const entry of parseEntries(acceptLanguage)) {
    const locale = supported(entry.tag);
    if (locale !== null) return locale;
  }
  return DEFAULT_LOCALE;
}
