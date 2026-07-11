// Timestamp formatting for the exception CLI. Pure (no I/O). Duration parsing
// and the scope caps moved to @akasecurity/schema (exception-scope), shared with the
// web-ui; what stays here is terminal-only rendering.
import { HOUR_MS, MINUTE_MS } from '@akasecurity/schema';

/**
 * Relative rendering of an ISO instant against `now`: 'in 42m' / '3h ago',
 * single largest unit (d/h/m), '—' for null (no expiry).
 */
export function formatRelative(iso: string | null, now = Date.now()): string {
  if (iso === null) return '—';
  const delta = Date.parse(iso) - now;
  const abs = Math.abs(delta);
  const days = Math.floor(abs / (24 * HOUR_MS));
  const hours = Math.floor(abs / HOUR_MS);
  const minutes = Math.floor(abs / MINUTE_MS);
  const label =
    days >= 1
      ? `${String(days)}d`
      : hours >= 1
        ? `${String(hours)}h`
        : minutes >= 1
          ? `${String(minutes)}m`
          : '<1m';
  return delta >= 0 ? `in ${label}` : `${label} ago`;
}

/** `YYYY-MM-DD HH:MM` (UTC), matching how `aka stats` renders timestamps. */
export function formatTimestamp(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ');
}
