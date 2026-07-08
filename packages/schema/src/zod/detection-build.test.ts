import { describe, expect, it } from 'vitest';

import type { DetectionRowInput } from './detection-build.ts';
import { rowToDetectionDetail } from './detection-build.ts';
import type { Rule } from './rule.ts';

function rule(id: string, matcher: Rule['matcher']): Rule {
  return { specVersion: 1, id, name: id, category: 'secret', severity: 'high', matcher };
}

function row(rules: Rule[]): DetectionRowInput {
  return {
    namespace: 'aka',
    packId: 'mixed',
    version: '1.0.0',
    name: 'Mixed',
    enabled: true,
    updatedAt: new Date(0),
    rules,
  };
}

describe('rowToDetectionDetail', () => {
  it('exposes regex, keyword, and validator rules alike, with ruleCount matching the list', () => {
    const detail = rowToDetectionDetail(
      row([
        rule('mixed/re', { type: 'regex', pattern: 'x', flags: 'g' }),
        rule('mixed/kw', { type: 'keyword', keywords: ['a'], caseSensitive: false }),
        rule('mixed/val', { type: 'validator', name: 'luhn' }),
      ]),
      0,
      null,
    );

    expect(detail.rules.map((r) => r.id)).toEqual(['mixed/re', 'mixed/kw', 'mixed/val']);
    expect(detail.rules.map((r) => r.matcher.type)).toEqual(['regex', 'keyword', 'validator']);
    // For a well-formed pack the header count equals the rules actually shown.
    expect(detail.ruleCount).toBe(3);
    expect(detail.rules.length).toBe(detail.ruleCount);
  });

  it('skips a rule whose matcher is missing/unknown but still counts it toward ruleCount', () => {
    // The OSS store parses rules_json tolerantly, so a foreign/partial row can
    // carry a rule with no matcher — it must not appear in the inspector, and
    // must not crash the read.
    const partial = { id: 'mixed/x', name: 'x', category: 'secret', severity: 'high' };
    const detail = rowToDetectionDetail(row([partial as unknown as Rule]), 0, null);

    expect(detail.rules).toEqual([]);
    expect(detail.ruleCount).toBe(1);
  });

  it('skips a matcher with the right type tag but a missing field (structurally invalid)', () => {
    // A tampered/foreign row can carry `{ type: 'keyword' }` with no `keywords`.
    // The type tag alone would pass a naive check and then crash the inspector
    // (matcher.keywords.map). Validate the whole matcher and drop the rule.
    const good = rule('pack/good', { type: 'regex', pattern: 'x', flags: 'g' });
    const bad = {
      id: 'pack/bad',
      name: 'bad',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'keyword' }, // no `keywords`
    };
    const detail = rowToDetectionDetail(row([good, bad as unknown as Rule]), 0, null);

    // Only the well-formed rule is exposed; the malformed one is dropped but
    // still counted in ruleCount (the pack's on-disk size).
    expect(detail.rules.map((r) => r.id)).toEqual(['pack/good']);
    expect(detail.ruleCount).toBe(2);
  });
});
