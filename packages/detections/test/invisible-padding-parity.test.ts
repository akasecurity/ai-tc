import { stripInvisiblePadding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { normalizeFormatChars } from '../src/format-chars.ts';

// A value's identity (the fingerprint behind exceptions and grants) ignores
// `stripInvisiblePadding`'s set; matching ignores the wider \p{Cf} class. If the
// identity set ever grew past the matching set, a padded occurrence could be
// the same credential to an exception yet never be detected as one match. Walk
// every code point so neither definition can drift from the other unnoticed.
describe('identity padding set is a subset of the matching set', () => {
  it('every code point the identity helper strips is also stripped for matching', () => {
    const offenders: string[] = [];
    let stripped = 0;
    for (let point = 0; point <= 0x10ffff; point += 1) {
      if (point >= 0xd800 && point <= 0xdfff) continue; // lone surrogates
      const char = String.fromCodePoint(point);
      if (stripInvisiblePadding(char) !== '') continue;
      stripped += 1;
      if (normalizeFormatChars(char)?.normalized !== '') offenders.push(point.toString(16));
    }
    expect(stripped).toBeGreaterThan(0);
    expect(offenders).toEqual([]);
  });

  it('matching strips more than identity does (ZWJ is matched past but kept in identity)', () => {
    expect(normalizeFormatChars('a‍b')?.normalized).toBe('ab');
    expect(stripInvisiblePadding('a‍b')).toBe('a‍b');
  });
});
