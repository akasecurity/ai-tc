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
