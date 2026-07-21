// Presentation helper: humanize an ISO timestamp as a relative string. Lives in
// @akasecurity/dashboard-ui so the shared findings views don't reach into an app; both
// the Vite dashboard and the OSS web-ui render the same "6 days ago" strings.

const RELATIVE = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

/** Humanize an ISO timestamp as a relative string ("6 days ago"). */
export function relativeTime(iso: string | undefined): string {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const deltaSec = (then - Date.now()) / 1000;
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
 */
export function relativeTimeShort(iso: string | undefined): string {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const abs = Math.abs((then - Date.now()) / 1000);
  if (abs < 45) return 'now';
  for (const [unit, secs] of UNITS) {
    if (abs >= secs) return `${String(Math.floor(abs / secs))}${SHORT_SUFFIX[unit] ?? ''}`;
  }
  return 'now';
}
