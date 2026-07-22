// Display labels for the time-range picker, used by the TimeRangeSelect
// component and any page that drives widgets off a range. Kept out of page
// modules so the component doesn't depend on a specific page.
//
// The vocabulary itself — the values, the default, and the lookback each range
// stands for — belongs to @akasecurity/schema and is re-exported here, so the
// picker and the query contracts read one set of constants, not two copies.

import { RANGE_DAYS, type TimeRange } from '@akasecurity/schema';

export { DEFAULT_TIME_RANGE, RANGE_DAYS, type TimeRange } from '@akasecurity/schema';

export interface TimeRangeOption {
  value: TimeRange;
  label: string;
}

/** Each range paired with the label the picker renders for it. */
export const TIME_RANGE_OPTIONS: TimeRangeOption[] = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '3m', label: 'Last 3 months' },
  { value: '6m', label: 'Last 6 months' },
];

const DAY_MS = 86_400_000;

/**
 * A time-range chip → the ISO `from` lower bound (`now − N days`) an API filters
 * on. Shared by every page that turns a range into a session/activity query so
 * every host path derives the same
 * bound. `now` is injectable so the derived `from` is testable.
 */
export function rangeToFromIso(range: TimeRange, now: number = Date.now()): string {
  return new Date(now - RANGE_DAYS[range] * DAY_MS).toISOString();
}

// Minute/hour-granularity lookback for the exceptions page's "Recently
// blocked" ledger — a distinct scale from the day-granularity TimeRange
// above, which drives historical activity/security widgets.
export type BlockedWindow = '30m' | '1h' | '4h' | '24h';

export interface BlockedWindowOption {
  value: BlockedWindow;
  label: string;
}

export const BLOCKED_WINDOWS: BlockedWindowOption[] = [
  { value: '30m', label: 'Last 30 minutes' },
  { value: '1h', label: 'Last hour' },
  { value: '4h', label: 'Last 4 hours' },
  { value: '24h', label: 'Last 24 hours' },
];

export const DEFAULT_BLOCKED_WINDOW: BlockedWindow = '30m';

const MINUTE_MS = 60_000;

/** A blocked-window chip → its span in milliseconds, for the `recentBlocked` query. */
export const BLOCKED_WINDOW_MS: Record<BlockedWindow, number> = {
  '30m': 30 * MINUTE_MS,
  '1h': 60 * MINUTE_MS,
  '4h': 4 * 60 * MINUTE_MS,
  '24h': 24 * 60 * MINUTE_MS,
};

/** The lowercase phrase the "Recently blocked" banner slots into its sentence. */
export const BLOCKED_WINDOW_PHRASE: Record<BlockedWindow, string> = {
  '30m': 'the last 30 minutes',
  '1h': 'the last hour',
  '4h': 'the last 4 hours',
  '24h': 'the last 24 hours',
};

/**
 * Coerce an untrusted `?window=` query value to a valid BlockedWindow, falling
 * back to the default. Uses Object.hasOwn rather than `in` so inherited keys
 * (`toString`, `constructor`, …) can't slip through and resolve to a function
 * instead of a millisecond value.
 */
export function resolveBlockedWindow(raw: string | undefined): BlockedWindow {
  return raw !== undefined && Object.hasOwn(BLOCKED_WINDOW_MS, raw)
    ? (raw as BlockedWindow)
    : DEFAULT_BLOCKED_WINDOW;
}
