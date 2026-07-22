// The time-window vocabulary shared by every range-driven surface: the dashboard
// pickers, the security and activity queries, the persistence repositories, and
// `aka stats`. One file owns the values, the default, and the lookback each range
// stands for, so a window can't mean 7 days in one package and 30 in another.
//
// Depends on nothing but zod — the widget contracts in security.ts import from
// here, never the reverse.

import { z } from 'zod';

export const TIME_RANGES = ['7d', '30d', '3m', '6m'] as const;

// Carries a component id because it is echoed inside response bodies. Query
// schemas re-declare an INLINE `z.enum(TIME_RANGES)` instead of reusing this
// one, so the OpenAPI generator expands `range` as a plain parameter rather
// than a $ref (params cannot be a $ref).
export const TimeRange = z.enum(TIME_RANGES).meta({ id: 'TimeRange' });
export type TimeRange = z.infer<typeof TimeRange>;

// The window a surface opens on when the caller supplies none.
export const DEFAULT_TIME_RANGE: TimeRange = '7d';

// Lookback per range, in days. 3m/6m are 90/180-day rolling approximations (no
// calendar-month math) — fine for a rolling dashboard window. `satisfies` keeps
// a missing range a compile error; `as const` keeps the table read-only, since
// four packages now share this one object.
export const RANGE_DAYS = {
  '7d': 7,
  '30d': 30,
  '3m': 90,
  '6m': 180,
} as const satisfies Record<TimeRange, number>;

const TIME_RANGE_OR_DEFAULT = TimeRange.catch(DEFAULT_TIME_RANGE);

/**
 * Coerce an untrusted value — a `?range=` URL param, an `aka stats --range`
 * flag — to a supported range, falling back to the default. Surfaces that read
 * a range off the outside world parse it here, so a missing or unsupported
 * value resolves to the same window on every surface.
 */
export function parseTimeRange(value: string | undefined): TimeRange {
  return TIME_RANGE_OR_DEFAULT.parse(value);
}
