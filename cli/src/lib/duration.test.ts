import { describe, expect, it } from 'vitest';

import { formatRelative } from './duration.ts';

describe('formatRelative', () => {
  const now = Date.parse('2026-07-03T12:00:00.000Z');

  it('renders the single largest unit, both directions', () => {
    expect(formatRelative('2026-07-03T12:42:00.000Z', now)).toBe('in 42m');
    expect(formatRelative('2026-07-03T15:00:00.000Z', now)).toBe('in 3h');
    expect(formatRelative('2026-07-05T12:00:00.000Z', now)).toBe('in 2d');
    expect(formatRelative('2026-07-03T09:00:00.000Z', now)).toBe('3h ago');
    expect(formatRelative('2026-07-03T12:00:30.000Z', now)).toBe('in <1m');
  });

  it('renders null (no expiry) as an em dash', () => {
    expect(formatRelative(null, now)).toBe('—');
  });
});
