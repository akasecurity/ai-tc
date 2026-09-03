// Presentation helper: humanize an ISO timestamp as a relative string. Lives in
// @akasecurity/dashboard-ui so the shared findings views don't reach into an app;
// every host renders the same "6 days ago" strings.
//
// Both helpers take the instant to measure against as a REQUIRED argument, and
// that is the whole point of the signature rather than a convenience. A relative
// label is a pure function of (timestamp, now); read `now` from the ambient clock
// instead and the same component computes one string while the server renders it
// and a different one when the browser hydrates it, whenever a rounding boundary
// falls between the two. React reports that as a hydration mismatch and discards
// the server HTML for the subtree. A default argument does not close this: it
// reads as safe at every call site that omits it, which is every call site until
// somebody remembers. Requiring the argument makes the compiler name each place
// that has to decide which instant it means. `useRenderClock` is what a client
// host passes; a server component passes one instant it captured itself.

const RELATIVE = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

/**
 * Humanize an ISO timestamp as a relative string ("6 days ago").
 *
 * @param iso the instant being described; a missing or unparseable value reads
 *   as the empty string, so a caller never has to pre-check one.
 * @param now the instant to measure against, in epoch milliseconds. Required —
 *   see the note at the top of this file.
 */
export function relativeTime(iso: string | undefined, now: number): string {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const deltaSec = (then - now) / 1000;
  const abs = Math.abs(deltaSec);
  if (abs < 45) return 'just now';
  for (const [unit, secs] of UNITS) {
    if (abs >= secs) return RELATIVE.format(Math.round(deltaSec / secs), unit);
  }
  return 'just now';
}

// Terse unit suffixes for relativeTimeShort, keyed by the same units as `UNITS`
// above so the two helpers can never drift on tier boundaries.
const SHORT_SUFFIX: Partial<Record<Intl.RelativeTimeFormatUnit, string>> = {
  year: 'y',
  month: 'mo',
  week: 'w',
  day: 'd',
  hour: 'h',
  minute: 'm',
};

/**
 * Terse relative age for compact feeds where the long form ("2 minutes ago")
 * won't fit a narrow column: "2m" · "14m" · "1h" · "3d" · "2w" · "3mo" · "1y".
 * Weeks cap at "4w" — the `month` tier (30d) precedes `week`, so 30+ days read
 * as "1mo"+. Under a minute reads "now" (same 45s cutoff as {@link relativeTime}'s
 * "just now"). Floors to the whole unit — "1h" means at least an hour elapsed.
 *
 * @param iso the instant being described; a missing or unparseable value reads
 *   as the empty string.
 * @param now the instant to measure against, in epoch milliseconds. Required for
 *   the reason {@link relativeTime}'s is — and this helper floors rather than
 *   rounds, so it crosses a boundary on every whole unit rather than on every
 *   half one, which makes a drifting `now` MORE likely to change its text, not
 *   less.
 */
export function relativeTimeShort(iso: string | undefined, now: number): string {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const abs = Math.abs((then - now) / 1000);
  if (abs < 45) return 'now';
  for (const [unit, secs] of UNITS) {
    if (abs >= secs) return `${String(Math.floor(abs / secs))}${SHORT_SUFFIX[unit] ?? ''}`;
  }
  return 'now';
}
