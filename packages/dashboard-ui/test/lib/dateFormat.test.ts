import { describe, expect, it } from 'vitest';

import { withRuntimeLocale } from '../../../../test/helpers/runtime-locale.ts';
import { eventTime, startLabel } from '../../src/activity/format.ts';
import { formatDateTime } from '../../src/lib/dateFormat.ts';

const UTC_DAY: Intl.DateTimeFormatOptions = { month: 'short', day: 'numeric', timeZone: 'UTC' };
const UTC_CLOCK: Intl.DateTimeFormatOptions = {
  hour: 'numeric',
  minute: '2-digit',
  timeZone: 'UTC',
};
const AT = Date.parse('2026-06-08T21:05:00.000Z');

describe('formatDateTime', () => {
  it('formats in the locale it is given', () => {
    expect(formatDateTime(AT, 'en-US', UTC_DAY)).toBe('Jun 8');
    expect(formatDateTime(AT, 'de-DE', UTC_DAY)).toBe('8. Juni');
  });

  it('keeps one formatter per locale apart for one options object', () => {
    expect(formatDateTime(AT, 'de-DE', UTC_CLOCK)).toBe('21:05');
    expect(formatDateTime(AT, 'en-US', UTC_CLOCK)).toMatch(/^9:05\sPM$/);
    expect(formatDateTime(AT, 'de-DE', UTC_CLOCK)).toBe('21:05');
  });

  it('falls back to en-US for a locale that is not a tag, rather than throwing', () => {
    for (const bad of ['', 'en_US', 'not a locale']) {
      expect(() => new Intl.DateTimeFormat(bad, UTC_DAY)).toThrow(RangeError);
      expect(formatDateTime(AT, bad, UTC_DAY)).toBe('Jun 8');
    }
  });

  it('still surfaces an invalid OPTION, which is a caller bug rather than input', () => {
    const bogus = { timeZone: 'Not/AZone' } as Intl.DateTimeFormatOptions;
    expect(() => formatDateTime(AT, 'en-US', bogus)).toThrow(RangeError);
  });

  it('reads an unparseable instant as empty rather than throwing', () => {
    // Intl throws a RangeError on NaN, which would take a whole list down for
    // one malformed timestamp.
    expect(() => new Intl.DateTimeFormat('en-US').format(Number.NaN)).toThrow(RangeError);
    expect(formatDateTime(Date.parse('not a date'), 'en-US', UTC_DAY)).toBe('');
  });

  it('does not read the runtime default locale', () => {
    // The control first: under the stand-in the runtime default really moved.
    withRuntimeLocale('en-US', () => {
      expect(new Date(AT).toLocaleDateString(undefined, UTC_DAY)).toBe('Jun 8');
      expect(formatDateTime(AT, 'de-DE', UTC_DAY)).toBe('8. Juni');
    });
    withRuntimeLocale('de-DE', () => {
      expect(new Date(AT).toLocaleDateString(undefined, UTC_DAY)).toBe('8. Juni');
      expect(formatDateTime(AT, 'en-US', UTC_DAY)).toBe('Jun 8');
    });
  });
});

describe('the activity time labels', () => {
  // Local time, so the expected strings are built from the same instant's local
  // fields rather than written for one runner's zone.
  const iso = new Date(2026, 6, 5, 21, 5, 9).toISOString();

  it('formats a session start in the reader’s clock convention', () => {
    expect(startLabel(iso, 'de-DE')).toBe('21:05');
    expect(startLabel(iso, 'en-US')).toMatch(/^9:05\sPM$/);
  });

  it('keeps the timeline at 24 hours with seconds, in the locale’s separators', () => {
    expect(eventTime(iso, 'en-US')).toBe('21:05:09');
    expect(eventTime(iso, 'de-DE')).toBe('21:05:09');
    // en-US and de-DE agree on this format, so they cannot tell a passed locale
    // from the runtime's; fi-FI separates with dots.
    expect(eventTime(iso, 'fi-FI')).toBe('21.05.09');
  });

  it('formats nothing for a malformed timestamp', () => {
    expect(startLabel('nope', 'en-US')).toBe('');
    expect(eventTime('nope', 'en-US')).toBe('');
  });

  it('ignores the runtime default locale', () => {
    withRuntimeLocale('en-US', () => {
      expect(startLabel(iso, 'de-DE')).toBe('21:05');
      expect(eventTime(iso, 'fi-FI')).toBe('21.05.09');
    });
    withRuntimeLocale('fi-FI', () => {
      // The control: under this stand-in the runtime's own format really moved.
      const timeline: Intl.DateTimeFormatOptions = {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hourCycle: 'h23',
      };
      expect(new Date(iso).toLocaleTimeString([], timeline)).toBe('21.05.09');
      expect(eventTime(iso, 'en-US')).toBe('21:05:09');
    });
  });
});
