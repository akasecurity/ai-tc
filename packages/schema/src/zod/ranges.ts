// The time-window vocabulary shared by every range-driven surface: the dashboard
// pickers, the security and activity queries, the persistence repositories, and
// `aka stats`. One file owns the values, the default, and the lookback each range
// stands for, so a window can't mean 7 days in one package and 30 in another.
//
// Depends on nothing but zod — the widget contracts in security.ts import from
// here, never the reverse.

import { z } from 'zod';

export const TIME_RANGES = ['7d', '30d', '3m', '6m'] as const;

export const TimeRange = z.enum(TIME_RANGES).meta({ id: 'TimeRange' });
export type TimeRange = z.infer<typeof TimeRange>;

// The window a surface opens on when the caller supplies none.
export const DEFAULT_TIME_RANGE: TimeRange = '7d';

// Lookback per range, in days. 3m/6m are 90/180-day rolling approximations (no
// calendar-month math) — fine for a rolling dashboard window.
export const RANGE_DAYS: Record<TimeRange, number> = { '7d': 7, '30d': 30, '3m': 90, '6m': 180 };
