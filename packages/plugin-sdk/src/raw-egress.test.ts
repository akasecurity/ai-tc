import { describe, expect, it } from 'vitest';

import { assertRawFree, maskContextSlice, RawEgressError, safeMaskedMatch } from './raw-egress.ts';

describe('maskContextSlice', () => {
  it('rebases a span onto a slice with a nonzero start', () => {
    const full = '0123456789 the secret is SECRET1234 in this text';
    const sliceStart = 5;
    const slice = full.slice(sliceStart);
    const spanStart = full.indexOf('SECRET1234');
    const spanEnd = spanStart + 'SECRET1234'.length;

    const masked = maskContextSlice(slice, sliceStart, [
      { rawMatch: 'SECRET1234', span: { start: spanStart, end: spanEnd } },
    ]);

    expect(masked).not.toContain('SECRET1234');
    expect(masked).toContain('[REDACTED:SECRET]');
  });

  it('masks two secrets inside one window', () => {
    const slice = 'alpha SECRET1234 middle SECRET5678 omega';
    const firstStart = slice.indexOf('SECRET1234');
    const secondStart = slice.indexOf('SECRET5678');

    const masked = maskContextSlice(slice, 0, [
      {
        rawMatch: 'SECRET1234',
        span: { start: firstStart, end: firstStart + 'SECRET1234'.length },
      },
      {
        rawMatch: 'SECRET5678',
        span: { start: secondStart, end: secondStart + 'SECRET5678'.length },
      },
    ]);

    expect(masked).not.toContain('SECRET1234');
    expect(masked).not.toContain('SECRET5678');
  });

  it('throws RawEgressError when a stale span misses the raw value', () => {
    const slice = 'the value SECRET1234 leaked here';

    expect(() =>
      maskContextSlice(slice, 0, [{ rawMatch: 'SECRET1234', span: { start: 0, end: 3 } }]),
    ).toThrow(RawEgressError);
  });
});

describe('safeMaskedMatch', () => {
  it('falls back to *** for a short-local-part email', () => {
    expect(safeMaskedMatch('a@b.com')).toBe('***');
  });

  it('still masks an ordinary secret', () => {
    const masked = safeMaskedMatch('SECRET1234');
    expect(masked).not.toBe('SECRET1234');
    expect(masked).not.toContain('SECRET1234');
  });
});

describe('assertRawFree', () => {
  it('passes clean text through unchanged', () => {
    expect(assertRawFree('nothing sensitive here', ['SECRET1234'])).toBe('nothing sensitive here');
  });

  it('throws when a raw value survives verbatim', () => {
    expect(() => assertRawFree('leaked SECRET1234 here', ['SECRET1234'])).toThrow(RawEgressError);
  });
});
