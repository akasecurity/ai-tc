import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { relativeTime, relativeTimeShort } from '../../src/lib/relativeTime.ts';

// Anchor "now" so the age math is deterministic regardless of when the suite runs.
const NOW = new Date('2026-06-21T12:00:00Z');
const ago = (ms: number) => new Date(NOW.getTime() - ms).toISOString();
const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

// Both helpers take the instant as a required argument, so every case below
// passes NOW explicitly. The fake clock is still set — deliberately, and to a
// DIFFERENT instant — because it is what makes each case double as a guard: a
// helper that reached for Date.now() would measure against an ambient clock a
// year and a half out, and no assertion here could still hold. Set the ambient
// clock to NOW and this whole file goes on passing with the argument ignored.
const AMBIENT = new Date('2027-12-25T00:00:00Z');

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(AMBIENT);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('relativeTimeShort', () => {
  it('reads "now" under the 45s cutoff', () => {
    expect(relativeTimeShort(ago(0), NOW.getTime())).toBe('now');
    expect(relativeTimeShort(ago(44 * SEC), NOW.getTime())).toBe('now');
  });

  it('floors to the largest whole unit with a terse suffix', () => {
    expect(relativeTimeShort(ago(2 * MIN), NOW.getTime())).toBe('2m');
    expect(relativeTimeShort(ago(38 * MIN), NOW.getTime())).toBe('38m');
    expect(relativeTimeShort(ago(90 * MIN), NOW.getTime())).toBe('1h'); // floors, not rounds
    expect(relativeTimeShort(ago(2 * HOUR), NOW.getTime())).toBe('2h');
    expect(relativeTimeShort(ago(3 * DAY), NOW.getTime())).toBe('3d');
    expect(relativeTimeShort(ago(2 * WEEK), NOW.getTime())).toBe('2w');
    expect(relativeTimeShort(ago(29 * DAY), NOW.getTime())).toBe('4w'); // weeks cap here — month tier starts at 30d
    expect(relativeTimeShort(ago(40 * DAY), NOW.getTime())).toBe('1mo'); // covers the `month` suffix the loop can emit
    expect(relativeTimeShort(ago(400 * DAY), NOW.getTime())).toBe('1y');
  });

  it('returns empty for a missing or unparseable timestamp', () => {
    expect(relativeTimeShort(undefined, NOW.getTime())).toBe('');
    expect(relativeTimeShort('not-a-date', NOW.getTime())).toBe('');
  });
});

describe('relativeTime', () => {
  it('uses a supplied render time instead of the current clock', () => {
    const blockedAt = new Date(NOW.getTime() - 29 * MIN - 29 * SEC).toISOString();

    expect(relativeTime(blockedAt, NOW.getTime())).toBe('29 minutes ago');
    expect(relativeTime(blockedAt, NOW.getTime() + 2 * SEC)).toBe('30 minutes ago');
  });

  it('returns empty for a missing or unparseable timestamp', () => {
    expect(relativeTime(undefined, NOW.getTime())).toBe('');
    expect(relativeTime('not-a-date', NOW.getTime())).toBe('');
  });
});

// The reason both helpers require the argument: a page is rendered twice, and a
// helper measuring against a clock that moved between the two renders produces
// different text for the same timestamp. These are the boundaries where that
// shows, driven as two calls that differ ONLY in `now` — which is the whole
// difference between a server render and the hydration that follows it.
describe('the boundary a drifting clock crosses', () => {
  it('changes the long form when the render instant moves by two seconds', () => {
    // The step is at 60s, not at the 45s cutoff: anything under a minute misses
    // every tier in UNITS and falls through to the same "just now" the cutoff
    // returns, so 45-60s is a second path to one answer rather than a boundary.
    const at = new Date(NOW.getTime() - 59 * SEC - 500).toISOString();
    expect(relativeTime(at, NOW.getTime())).toBe('just now');
    expect(relativeTime(at, NOW.getTime() + 2 * SEC)).toBe('1 minute ago');
  });

  it('changes the short form on a whole-unit boundary, which it floors to', () => {
    // Two seconds either side of a whole hour: the short form floors, so it
    // steps at every whole unit rather than at every half one.
    const at = new Date(NOW.getTime() - HOUR + SEC).toISOString();
    expect(relativeTimeShort(at, NOW.getTime())).toBe('59m');
    expect(relativeTimeShort(at, NOW.getTime() + 2 * SEC)).toBe('1h');
  });
});

describe('relativeTime', () => {
  it('uses a supplied render time instead of the current clock', () => {
    const blockedAt = new Date(NOW.getTime() - 29 * MIN - 29 * SEC).toISOString();

    expect(relativeTime(blockedAt, NOW.getTime())).toBe('29 minutes ago');
    expect(relativeTime(blockedAt, NOW.getTime() + 2 * SEC)).toBe('30 minutes ago');
  });
});
