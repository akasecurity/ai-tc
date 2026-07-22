import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { relativeTimeShort } from '../../src/lib/relativeTime.ts';

// Anchor "now" so the age math is deterministic regardless of when the suite runs.
const NOW = new Date('2026-06-21T12:00:00Z');
const ago = (ms: number) => new Date(NOW.getTime() - ms).toISOString();
const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

describe('relativeTimeShort', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('reads "now" under the 45s cutoff', () => {
    expect(relativeTimeShort(ago(0))).toBe('now');
    expect(relativeTimeShort(ago(44 * SEC))).toBe('now');
  });

  it('floors to the largest whole unit with a terse suffix', () => {
    expect(relativeTimeShort(ago(2 * MIN))).toBe('2m');
    expect(relativeTimeShort(ago(38 * MIN))).toBe('38m');
    expect(relativeTimeShort(ago(90 * MIN))).toBe('1h'); // floors, not rounds
    expect(relativeTimeShort(ago(2 * HOUR))).toBe('2h');
    expect(relativeTimeShort(ago(3 * DAY))).toBe('3d');
    expect(relativeTimeShort(ago(2 * WEEK))).toBe('2w');
    expect(relativeTimeShort(ago(29 * DAY))).toBe('4w'); // weeks cap here — month tier starts at 30d
    expect(relativeTimeShort(ago(40 * DAY))).toBe('1mo'); // covers the `month` suffix the loop can emit
    expect(relativeTimeShort(ago(400 * DAY))).toBe('1y');
  });

  it('returns "" for missing or unparseable input', () => {
    expect(relativeTimeShort(undefined)).toBe('');
    expect(relativeTimeShort('not-a-date')).toBe('');
  });
});
