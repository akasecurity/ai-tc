import { describe, expect, it } from 'vitest';

import type { DetectionRowInput } from '../../src/zod/detection-build.ts';
import { rowToDetectionDetail } from '../../src/zod/detection-build.ts';
import type { Rule } from '../../src/zod/rule.ts';

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
  it('exposes every matcher kind alike, with ruleCount matching the list', () => {
    const detail = rowToDetectionDetail(
      row([
        rule('mixed/re', { type: 'regex', pattern: 'x', flags: 'g' }),
        rule('mixed/kw', { type: 'keyword', keywords: ['a'], caseSensitive: false }),
        rule('mixed/cap', { type: 'regex', pattern: 'k=(\\w+)', flags: 'g', captureGroup: 1 }),
      ]),
      0,
      null,
    );

    expect(detail.rules.map((r) => r.id)).toEqual(['mixed/re', 'mixed/kw', 'mixed/cap']);
    expect(detail.rules.map((r) => r.matcher.type)).toEqual(['regex', 'keyword', 'regex']);
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

  // A matcher alone does not decide whether a rule fires. Half the bundled
  // catalog (50 of 101 rules) carries at least one of these three, so a consumer
  // that re-runs a rule from this shape — a preview, a tester — evaluated
  // something the engine never runs: no false-positive guard, and no file
  // scoping. `examples` is on all 101.
  it('carries the fields that decide whether a rule fires, not just the matcher', () => {
    const scoped: Rule = {
      ...rule('pack/scoped', { type: 'regex', pattern: 'sk-[a-z]+', flags: 'g' }),
      appliesTo: { extensions: ['.py'] },
      postValidators: ['entropy'],
      requiresNearby: { labels: ['api_key'], windowChars: 160 },
      examples: ['sk-abcdef'],
    };

    const [carried] = rowToDetectionDetail(row([scoped]), 0, null).rules;

    expect(carried).toMatchObject({
      appliesTo: { extensions: ['.py'] },
      postValidators: ['entropy'],
      requiresNearby: { labels: ['api_key'], windowChars: 160 },
      examples: ['sk-abcdef'],
    });
  });

  // A rule that sets none of them must not sprout keys holding `undefined`.
  // This detail is serialized to JSON on the enterprise HTTP path, where absent
  // and explicitly-undefined are the same thing — but they are NOT the same to a
  // strict deep-equality assertion or to `in`, and absent is what "the rule does
  // not set this" looked like before the fields existed.
  it('leaves an unset field absent rather than present-and-undefined', () => {
    const bare = rule('pack/bare', { type: 'regex', pattern: 'x', flags: 'g' });

    const [built] = rowToDetectionDetail(row([bare]), 0, null).rules;

    expect(built).toBeDefined();
    for (const key of ['appliesTo', 'postValidators', 'requiresNearby', 'examples']) {
      expect(built).not.toHaveProperty(key);
    }
  });

  // The enrichment is per-field and best-effort, and this is what says so. The
  // store parses rules_json tolerantly, so one bad field must cost that field
  // and nothing else — a whole-rule parse here would drop the rule entirely and
  // turn a display improvement into rules vanishing from the inspector.
  it('omits only the field that fails validation, keeping the rule and its siblings', () => {
    const partlyBad = {
      ...rule('pack/partly-bad', { type: 'regex', pattern: 'x', flags: 'g' }),
      // Not a name the engine implements — PostValidatorRef refuses it.
      postValidators: ['ssn-checksum'],
      appliesTo: { extensions: ['.py'] },
    };

    const [built] = rowToDetectionDetail(row([partlyBad as unknown as Rule]), 0, null).rules;

    expect(built?.id).toBe('pack/partly-bad');
    expect(built).not.toHaveProperty('postValidators');
    expect(built?.appliesTo).toEqual({ extensions: ['.py'] });
  });

  // The inclusion test stays exactly what it was: a renderable matcher. A stored
  // rule missing `specVersion` predates the field or came from a tolerant
  // writer, and it rendered fine before — validating the whole `Rule` (which
  // pins `specVersion: 1` over a strict object) would silently start dropping it.
  it('still exposes a rule that would fail a whole-Rule parse', () => {
    const noSpecVersion = {
      id: 'pack/legacy',
      name: 'legacy',
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'x', flags: 'g' },
      examples: ['x'],
    };

    const detail = rowToDetectionDetail(row([noSpecVersion as unknown as Rule]), 0, null);

    expect(detail.rules.map((r) => r.id)).toEqual(['pack/legacy']);
    expect(detail.rules[0]?.examples).toEqual(['x']);
  });
});
