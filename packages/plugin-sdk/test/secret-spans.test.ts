import type { MatchResult } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { ISOLATED_SCAN_BUDGET_MS, ISOLATED_START_BUDGET_MS } from '../src/isolated-scan.ts';
import {
  createSecretSpanScanner,
  DEFAULT_SECRET_SCAN_BOUND,
  disjointSecretSpans,
  findSecretSpans,
  secretRulePartition,
} from '../src/secret-spans.ts';

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

describe('secret rules beyond the bundled packs', () => {
  const marker = ['ACME', 'TOK'].join('');
  const acmeValue = `${marker}${'7'.repeat(10)}`;
  const keywordRule: Rule = {
    specVersion: 1,
    id: 'acme/internal-token',
    name: 'Internal token',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'keyword', keywords: [acmeValue], caseSensitive: true },
  };
  const regexRule: Rule = {
    specVersion: 1,
    id: 'acme/internal-regex',
    name: 'Internal token by pattern',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: `${marker}[0-9]{10}`, flags: 'g' },
  };
  const piiRule: Rule = { ...keywordRule, id: 'acme/not-secret', category: 'pii' };

  it('adds installed secret rules to the bundled ones, and runs keyword rules in-process', () => {
    const partition = secretRulePartition([keywordRule, piiRule]);
    expect(partition.unverified).toEqual([]);
    expect(partition.verified.map((r) => r.id)).toContain('acme/internal-token');
    expect(partition.verified.map((r) => r.id)).toContain('secrets/github-pat');
    expect(partition.verified.map((r) => r.id)).not.toContain('acme/not-secret');
  });

  it('isolates an installed regex rule', () => {
    expect(secretRulePartition([regexRule]).unverified.map((r) => r.id)).toEqual([
      'acme/internal-regex',
    ]);
  });

  it('keeps a bundled rule verified when an installed copy re-ships it', () => {
    const bundled = secretRulePartition([]).verified.find((r) => r.id === 'secrets/github-pat');
    if (bundled === undefined) throw new Error('expected the bundled rule');
    const partition = secretRulePartition([{ ...bundled, name: 'renamed' }]);
    expect(partition.unverified).toEqual([]);
    expect(partition.verified.filter((r) => r.id === 'secrets/github-pat')).toHaveLength(1);
  });

  it('finds a value only an installed keyword rule matches', async () => {
    const scanner = createSecretSpanScanner(secretRulePartition([keywordRule]));
    try {
      const spans = await scanner.find(`x ${acmeValue} y`);
      expect(spans).toEqual([
        {
          start: 2,
          end: 2 + acmeValue.length,
          ruleId: 'acme/internal-token',
          category: 'secret',
          value: acmeValue,
        },
      ]);
    } finally {
      await scanner.close();
    }
  });

  it('finds a value only an installed regex rule matches, under the bound', async () => {
    const scanner = createSecretSpanScanner(secretRulePartition([regexRule]));
    try {
      const spans = await scanner.find(`x ${acmeValue} ${patShaped(5)}`);
      expect(spans.map((s) => s.ruleId)).toEqual(['acme/internal-regex', 'secrets/github-pat']);
    } finally {
      await scanner.close();
    }
  });

  it('throws when the bounded scan cannot finish', async () => {
    const scanner = createSecretSpanScanner(secretRulePartition([regexRule]), {
      budgetMs: 0,
      startBudgetMs: 0,
    });
    try {
      await expect(scanner.find(`x ${acmeValue}`)).rejects.toThrow();
    } finally {
      await scanner.close();
    }
  });

  it('never lets a rule sharing a bundled id switch the bundled matcher off', async () => {
    const shadow: Rule = {
      specVersion: 1,
      id: 'secrets/github-pat',
      name: 'Shadow',
      category: 'secret',
      severity: 'low',
      matcher: { type: 'keyword', keywords: ['never-present-keyword'], caseSensitive: true },
    };
    const partition = secretRulePartition([shadow]);
    expect(partition.verified.filter((r) => r.id === 'secrets/github-pat')).toHaveLength(2);
    const scanner = createSecretSpanScanner(partition);
    try {
      const value = patShaped(77);
      const spans = await scanner.find(`x ${value}`);
      expect(spans.map((sp) => sp.value)).toEqual([value]);
    } finally {
      await scanner.close();
    }
  });

  it('starts its worker under the SDK cold-start allowance by default', () => {
    expect(DEFAULT_SECRET_SCAN_BOUND.startBudgetMs).toBe(ISOLATED_START_BUDGET_MS);
    expect(DEFAULT_SECRET_SCAN_BOUND.budgetMs).toBe(ISOLATED_SCAN_BUDGET_MS);
  });
});
