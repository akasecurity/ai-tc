import { describe, expect, it } from 'vitest';

import { formatMttrDuration } from './format.ts';

describe('formatMttrDuration', () => {
  it('renders an em dash for null (no data for the bucket)', () => {
    expect(formatMttrDuration(null)).toBe('—');
  });

  it('renders minutes under an hour', () => {
    expect(formatMttrDuration(12 * 60_000)).toBe('12m');
  });

  it('never renders 0m for a sub-minute-but-defined duration', () => {
    expect(formatMttrDuration(1)).toBe('1m');
    expect(formatMttrDuration(0)).toBe('1m');
  });

  it('renders hours with no remainder minutes as just the hour', () => {
    expect(formatMttrDuration(3 * 60 * 60_000)).toBe('3h');
  });

  it('renders hours with remainder minutes', () => {
    expect(formatMttrDuration(3 * 60 * 60_000 + 15 * 60_000)).toBe('3h 15m');
  });

  it('renders days with no remainder hours as just the day', () => {
    expect(formatMttrDuration(2 * 24 * 60 * 60_000)).toBe('2d');
  });

  it('renders days with remainder hours', () => {
    expect(formatMttrDuration(2 * 24 * 60 * 60_000 + 4 * 60 * 60_000)).toBe('2d 4h');
  });

  it('does not roll a near-hour minute count up to a spurious 60m', () => {
    // 59.6 minutes rounds to 60m at the minute level — must carry into 1h, not
    // print "60m".
    expect(formatMttrDuration(59.6 * 60_000)).toBe('1h');
  });

  it('carries a minute count that rounds up to a full day into 1d, not 24h', () => {
    expect(formatMttrDuration(1439.6 * 60_000)).toBe('1d');
  });

  it('treats NaN as no data', () => {
    expect(formatMttrDuration(Number.NaN)).toBe('—');
  });
});
