import { describe, expect, it } from 'vitest';

import {
  DEFAULT_TIME_RANGE,
  parseTimeRange,
  RANGE_DAYS,
  TIME_RANGES,
  TimeRange,
} from '../../src/zod/ranges.ts';

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
});

describe('parseTimeRange', () => {
  it('accepts every supported range', () => {
    for (const range of TIME_RANGES) {
      expect(parseTimeRange(range)).toBe(range);
    }
  });

  it('falls back to the default for a missing or unsupported value', () => {
    expect(parseTimeRange(undefined)).toBe(DEFAULT_TIME_RANGE);
    expect(parseTimeRange('')).toBe(DEFAULT_TIME_RANGE);
    expect(parseTimeRange('1y')).toBe(DEFAULT_TIME_RANGE);
  });

  // Callers hand it raw URL params and CLI flags, so a non-string must resolve
  // to the default rather than throw.
  it('falls back for a non-string value', () => {
    expect(parseTimeRange(null)).toBe(DEFAULT_TIME_RANGE);
    expect(parseTimeRange(7)).toBe(DEFAULT_TIME_RANGE);
    expect(parseTimeRange(['7d'])).toBe(DEFAULT_TIME_RANGE);
  });
});
