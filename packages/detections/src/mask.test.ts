import { describe, expect, it } from 'vitest';

import { maskMatch } from './mask.ts';

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
