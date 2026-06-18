import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { epochMillisToIso, isoToEpochMillis } from './time.ts';

describe('time helpers', () => {
  it('round-trips: isoToEpochMillis(epochMillisToIso(x)) === x', () => {
    const ms = 1749571200000; // 2025-06-10T16:00:00.000Z
    expect(isoToEpochMillis(epochMillisToIso(ms))).toBe(ms);
  });

  it('epochMillisToIso output satisfies z.iso.datetime()', () => {
    const ms = 1749571200000;
    const iso = epochMillisToIso(ms);
    const result = z.iso.datetime().safeParse(iso);
    expect(result.success).toBe(true);
  });

  it('isoToEpochMillis of a known ISO returns the correct integer', () => {
    // 2026-06-10T14:00:00.000Z = 1749560400000
    const iso = '2026-06-10T14:00:00.000Z';
    const ms = isoToEpochMillis(iso);
    expect(ms).toBe(new Date(iso).getTime());
    expect(typeof ms).toBe('number');
    expect(Number.isInteger(ms)).toBe(true);
  });

  it('epochMillisToIso produces a valid ISO-8601 string for epoch 0', () => {
    expect(epochMillisToIso(0)).toBe('1970-01-01T00:00:00.000Z');
  });
});
