// Security widget display formatting — pure ms → human-string helpers. Lives
// with the views (not the apps) so both the Vite dashboard and the OSS web-ui
// render identical labels. `formatMttrDuration` mirrors the semantics of
// MttrTrendPoint.bySeverity: `null` means no resolutions fell in that bucket
// (no data point to average), never zero — so it renders as an em dash, not
// "0m".

const MINUTE_MS = 60_000;

/**
 * Humanize a mean-time-to-remediate duration in milliseconds: `2d 4h` / `3h` /
 * `12m`. Sub-minute (but non-null) durations round up to `1m` (never `0m`,
 * which would read as "instant"). `null` (no data for the bucket) renders as
 * `—`.
 */
export function formatMttrDuration(ms: number | null): string {
  if (ms === null || Number.isNaN(ms)) return '—';
  // Decompose hierarchically from a single rounded minute count — avoids the
  // rollover bugs a per-unit `Math.round` on days/hours/minutes independently
  // would introduce (e.g. 59.6 minutes rounding to a spurious "60m").
  let minutes = Math.round(Math.max(0, ms) / MINUTE_MS);
  const days = Math.floor(minutes / (24 * 60));
  minutes -= days * 24 * 60;
  const hours = Math.floor(minutes / 60);
  minutes -= hours * 60;

  if (days > 0) return hours > 0 ? `${String(days)}d ${String(hours)}h` : `${String(days)}d`;
  if (hours > 0) return minutes > 0 ? `${String(hours)}h ${String(minutes)}m` : `${String(hours)}h`;
  return `${String(Math.max(1, minutes))}m`;
}
