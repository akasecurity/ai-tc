import type { MatchResult } from '@akasecurity/detections';
import { describe, expect, it } from 'vitest';

import { disjointSecretSpans, findSecretSpans } from '../src/secret-spans.ts';

// A token-shaped value assembled at runtime, so no literal secret sits in the source.
function patShaped(seed: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = seed;
  let body = '';
  for (let i = 0; i < 36; i += 1) {
    state = (state * 1103515245 + 12345) % 2147483648;
    body += alphabet.charAt(state % alphabet.length);
  }
  return ['gh', 'p_', body].join('');
}

const email = ['jane.doe', 'example.com'].join('@');

describe('findSecretSpans', () => {
  it('finds a secret-category value with its rule', () => {
    const value = patShaped(7);
    const text = `use ${value} to push`;
    expect(findSecretSpans(text)).toEqual([
      {
        start: 4,
        end: 4 + value.length,
        ruleId: 'secrets/github-pat',
        category: 'secret',
        value,
      },
    ]);
  });

  it('leaves other categories alone', () => {
    expect(findSecretSpans(`mail ${email} today`)).toEqual([]);
  });

  it('finds nothing inside a sighting token or a vault pointer', () => {
    const token = ['[[aka:fp:v1.', patShaped(3).slice(0, 40), 'AbC', ']]'].join('');
    const pointer = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
    expect(findSecretSpans(`${token} ${pointer}`)).toEqual([]);
  });

  it('finds a value padded with an invisible character', () => {
    const value = patShaped(11);
    const padded = `${value.slice(0, 10)}\u200B${value.slice(10)}`;
    const [span] = findSecretSpans(`x ${padded} y`);
    expect(span?.value?.replace('\u200B', '')).toBe(value);
  });
});

describe('disjointSecretSpans', () => {
  const hit = (start: number, end: number, ruleId: string, text: string): MatchResult => ({
    ruleId,
    category: 'secret',
    severity: 'high',
    span: { start, end },
    rawMatch: text.slice(start, end),
    confidence: 1,
  });
  const text = 'aaaaBBBBccccDDDD';

  it('keeps the covering match of an overlapping group', () => {
    expect(
      disjointSecretSpans(text, [hit(4, 8, 'inner', text), hit(2, 10, 'outer', text)]),
    ).toEqual([{ start: 2, end: 10, ruleId: 'outer', category: 'secret', value: 'aaBBBBcc' }]);
  });

  it('gives no value to a group no single match covers', () => {
    expect(disjointSecretSpans(text, [hit(2, 6, 'a', text), hit(4, 10, 'b', text)])).toEqual([
      { start: 2, end: 10, ruleId: 'a', category: 'secret', value: undefined },
    ]);
  });

  it('drops out-of-range spans and orders the rest', () => {
    expect(
      disjointSecretSpans(text, [
        hit(12, 16, 'late', text),
        hit(0, 40, 'bad', text),
        hit(0, 2, 'early', text),
      ]),
    ).toEqual([
      { start: 0, end: 2, ruleId: 'early', category: 'secret', value: 'aa' },
      { start: 12, end: 16, ruleId: 'late', category: 'secret', value: 'DDDD' },
    ]);
  });
});
