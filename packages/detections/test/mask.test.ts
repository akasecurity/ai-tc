import { describe, expect, it } from 'vitest';

import { maskMatch } from '../src/mask.ts';

describe('maskMatch', () => {
  // Rule 1 — short match (length ≤ 5) → fixed token '***'
  it('length 1 → ***', () => {
    expect(maskMatch('a')).toBe('***');
  });

  it('length 3 → ***', () => {
    expect(maskMatch('abc')).toBe('***');
  });

  it('length 5 (boundary) → ***', () => {
    expect(maskMatch('12345')).toBe('***');
  });

  // Rule 2 — email
  it('email: alice@example.com → a****@example.com', () => {
    expect(maskMatch('alice@example.com')).toBe('a****@example.com');
  });

  it('email short local: ab@x.io → a*@x.io', () => {
    expect(maskMatch('ab@x.io')).toBe('a*@x.io');
  });

  it('email single-char local: a@b.com → a@b.com (nothing to mask)', () => {
    expect(maskMatch('a@b.com')).toBe('a@b.com');
  });

  // Rule 3 — generic ≥ 6 characters
  it('length 6 (boundary): abc123 → a******3', () => {
    expect(maskMatch('abc123')).toBe('a******3');
  });

  it('AWS key AKIAIOSFODNN7EXAMPLE → A******E', () => {
    expect(maskMatch('AKIAIOSFODNN7EXAMPLE')).toBe('A******E');
  });

  it('generic password → p******d', () => {
    expect(maskMatch('password')).toBe('p******d');
  });

  // Invariant: maskMatch(raw) !== raw for length > 1, EXCEPT single-char-local
  // emails (e.g. 'a@b.com') where Rule 2 reveals the whole local + full domain
  // and the output equals the input by design (asserted separately above).
  it('invariant: output never equals input for length > 1 (excluding single-char-local emails)', () => {
    const samples = [
      'ab',
      'abc',
      '12345',
      'abc123',
      'AKIAIOSFODNN7EXAMPLE',
      'alice@example.com',
      'ab@x.io',
    ];
    for (const raw of samples) {
      expect(maskMatch(raw)).not.toBe(raw);
    }
  });
});

// Invisible padding is removed before any rule runs, so the length rule, the
// email split and the first/last characters all read the visible value.
describe('maskMatch — invisible padding', () => {
  const PADDING = [
    ['zero width space', '\u200B'],
    ['left-to-right mark', '\u200E'],
    ['right-to-left mark', '\u200F'],
    ['Arabic letter mark', '\u061C'],
    ['Mongolian vowel separator', '\u180E'],
    ['interlinear annotation anchor', '\uFFF9'],
  ] as const;

  describe.each(PADDING)('padded with a %s', (_name, pad) => {
    it('generic: padding inside or at either edge masks like the clean value', () => {
      const clean = 'AKIAIOSFODNN7EXAMPLE';
      expect(maskMatch(`AKIAIOSF${pad}ODNN7EXAMPLE`)).toBe(maskMatch(clean));
      expect(maskMatch(`${pad}${clean}`)).toBe(maskMatch(clean));
      expect(maskMatch(`${clean}${pad}`)).toBe(maskMatch(clean));
    });

    it('short: a five-character value padded past the length boundary is still fully masked', () => {
      expect(maskMatch(`ab${pad}cde`)).toBe(maskMatch('abcde'));
      expect(maskMatch(`ab${pad}cde`)).toBe('***');
    });

    it('email: padding in the local part or the domain masks like the clean address', () => {
      const clean = 'alice@example.com';
      expect(maskMatch(`al${pad}ice@example.com`)).toBe(maskMatch(clean));
      expect(maskMatch(`alice@exa${pad}mple.com`)).toBe(maskMatch(clean));
      expect(maskMatch(`${pad}alice@example.com`)).toBe(maskMatch(clean));
    });

    it('email: a padded single-character local part masks like the clean one', () => {
      expect(maskMatch(`a${pad}@b.com`)).toBe('a@b.com');
    });
  });

  it('a zero width non-joiner is not padding: inside the domain it keeps its own masked value', () => {
    const clean = 'alice@example.com';
    const joined = 'alice@exa\u200Cmple.com';
    expect(maskMatch(joined)).not.toBe(maskMatch(clean));
    expect(maskMatch(joined)).toBe('a****@exa\u200Cmple.com');
  });

  it('different visible local-part lengths still mask differently when one is padded', () => {
    expect(maskMatch('alic\u200B@example.com')).not.toBe(maskMatch('alice@example.com'));
    expect(maskMatch('alic\u200B@example.com')).toBe(maskMatch('alic@example.com'));
  });
});
