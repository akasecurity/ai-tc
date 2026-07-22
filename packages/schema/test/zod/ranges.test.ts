import { describe, expect, it } from 'vitest';

import { DEFAULT_TIME_RANGE, RANGE_DAYS, TIME_RANGES, TimeRange } from '../../src/zod/ranges.ts';

describe('DEFAULT_TIME_RANGE', () => {
  it('is 7 days', () => {
    expect(DEFAULT_TIME_RANGE).toBe('7d');
    expect(RANGE_DAYS[DEFAULT_TIME_RANGE]).toBe(7);
  });

  it('is one of the supported ranges', () => {
    expect(TIME_RANGES).toContain(DEFAULT_TIME_RANGE);
  });
});

describe('TimeRange', () => {
  it('accepts every supported value', () => {
    for (const range of TIME_RANGES) {
      expect(TimeRange.safeParse(range).success).toBe(true);
    }
  });

  it('rejects a value outside the set', () => {
    expect(TimeRange.safeParse('1y').success).toBe(false);
    expect(TimeRange.safeParse('').success).toBe(false);
  });
});

describe('RANGE_DAYS', () => {
  it('gives every range a lookback', () => {
    for (const range of TIME_RANGES) {
      expect(RANGE_DAYS[range]).toBeGreaterThan(0);
    }
    expect(Object.keys(RANGE_DAYS).sort()).toEqual([...TIME_RANGES].sort());
  });

  it('treats 3m/6m as 90/180-day rolling windows', () => {
    expect(RANGE_DAYS).toEqual({ '7d': 7, '30d': 30, '3m': 90, '6m': 180 });
  });

  it('orders lookbacks the same way the ranges are listed', () => {
    const days = TIME_RANGES.map((r) => RANGE_DAYS[r]);
    expect(days).toEqual([...days].sort((a, b) => a - b));
  });
});
