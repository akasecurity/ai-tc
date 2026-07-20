import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import {
  FalsePositivePatternGroup,
  type TriageHit,
  type TriageRecommendation,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { deriveFalsePositivePatterns } from '../../src/triage/false-positive-patterns.ts';
import { planTriageWriteback } from '../../src/triage/writeback.ts';

// Assembled at runtime so the source carries no contiguous key-shaped literal —
// the value is an obviously-fake example, not a key.
const RAW_STRIPE = ['sk', 'live', '51H8xEXAMPLErawstripesecretVALUE0000'].join('_');
const RAW_AWS = 'AKIAIOSFODNN7EXAMPLE';

const hit = (over: Partial<TriageHit>): TriageHit => ({
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW_AWS,
  context: `export KEY=${RAW_AWS} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  ...over,
});

const recFor = (fpIds: string[], genuineCount = 0): TriageRecommendation => ({
  perCategory: [
    {
      category: 'secret',
      action: 'warn',
      reasoning: 'canonical fixture keys, marked as false positives',
      genuineCount,
      fpCount: fpIds.length,
      fpIds,
    },
  ],
  notes: 'looks routine',
});

describe('deriveFalsePositivePatterns — grounded masked FP-pattern signal for the fixture offer', () => {
  it('groups two marked FPs that share a re-derived masked token into one group', () => {
    const a = hit({ id: '0', rawMatch: RAW_AWS, valueFingerprint: 'ab'.repeat(32) });
    const b = hit({ id: '1', rawMatch: RAW_AWS, valueFingerprint: 'cd'.repeat(32) });
    const rec = recFor(['0', '1']);
    const plan = planTriageWriteback([a, b], rec);

    const groups = deriveFalsePositivePatterns([a, b], rec, plan);

    expect(groups).toHaveLength(1);
    const g = groups[0];
    if (g === undefined) throw new Error('expected one group');
    expect(g.pattern).toBe(safeMaskedMatch(RAW_AWS));
    expect(g.count).toBe(2);
    expect(g.values).toHaveLength(2);
    expect(g.values).toEqual(
      expect.arrayContaining([
        {
          ruleId: 'secrets/aws-access-key',
          category: 'secret',
          valueFingerprint: 'ab'.repeat(32),
          keyVersion: 1,
        },
        {
          ruleId: 'secrets/aws-access-key',
          category: 'secret',
          valueFingerprint: 'cd'.repeat(32),
          keyVersion: 1,
        },
      ]),
    );
    expect(FalsePositivePatternGroup.safeParse(g).success).toBe(true);
  });

  it('produces one group per distinct masked token', () => {
    const a = hit({ id: '0', rawMatch: RAW_AWS, valueFingerprint: 'ab'.repeat(32) });
    const b = hit({
      id: '1',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: 'cd'.repeat(32),
    });
    const rec = recFor(['0', '1']);
    const plan = planTriageWriteback([a, b], rec);

    const groups = deriveFalsePositivePatterns([a, b], rec, plan);

    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.pattern).sort()).toEqual(
      [safeMaskedMatch(RAW_AWS), safeMaskedMatch(RAW_STRIPE)].sort(),
    );
    expect(groups.every((g) => g.count === 1)).toBe(true);
  });

  it('returns empty when no hit is marked a false positive', () => {
    const a = hit({ id: '0' });
    const rec = recFor([], 1);
    const plan = planTriageWriteback([a], rec);

    expect(deriveFalsePositivePatterns([a], rec, plan)).toEqual([]);
  });

  it('re-derives the masked token from the raw value, never the streamed maskedMatch', () => {
    const a = hit({ id: '0', rawMatch: RAW_AWS, maskedMatch: 'TOTALLY-DIFFERENT-STREAMED-TOKEN' });
    const rec = recFor(['0']);
    const plan = planTriageWriteback([a], rec);

    const groups = deriveFalsePositivePatterns([a], rec, plan);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.pattern).toBe(safeMaskedMatch(RAW_AWS));
    expect(groups[0]?.pattern).not.toBe('TOTALLY-DIFFERENT-STREAMED-TOKEN');
  });

  it('counts a marked hit lacking full value identity but omits it from values, keeping the group keyable', () => {
    const keyed = hit({ id: '0', rawMatch: RAW_AWS, valueFingerprint: 'ab'.repeat(32) });
    const unkeyable = hit({ id: '1', rawMatch: RAW_AWS, valueFingerprint: undefined });
    const rec = recFor(['0', '1']);
    const plan = planTriageWriteback([keyed, unkeyable], rec);

    const groups = deriveFalsePositivePatterns([keyed, unkeyable], rec, plan);

    expect(groups).toHaveLength(1);
    const g = groups[0];
    if (g === undefined) throw new Error('expected one group');
    // Display count reflects BOTH marked hits sharing the token...
    expect(g.count).toBe(2);
    // ...but only the fully-identified hit contributes to `values` — the
    // unkeyable mark cannot back a written exception.
    expect(g.values).toEqual([
      {
        ruleId: 'secrets/aws-access-key',
        category: 'secret',
        valueFingerprint: 'ab'.repeat(32),
        keyVersion: 1,
      },
    ]);
    expect(FalsePositivePatternGroup.safeParse(g).success).toBe(true);
  });

  it('drops a marked hit entirely when it is the sole hit for its token and lacks value identity', () => {
    // No sibling hit shares this token, so a group could only be emitted with an
    // empty `values` array — invalid against FalsePositivePatternGroup's
    // values.min(1). Fail open: omit the group rather than emit a dead one.
    const keyed = hit({
      id: '0',
      ruleId: 'secrets/stripe-live-key',
      rawMatch: RAW_STRIPE,
      context: `token=${RAW_STRIPE}`,
      valueFingerprint: 'ab'.repeat(32),
    });
    const unkeyable = hit({ id: '1', rawMatch: RAW_AWS, valueFingerprint: undefined });
    const rec = recFor(['0', '1']);
    const plan = planTriageWriteback([keyed, unkeyable], rec);

    const groups = deriveFalsePositivePatterns([keyed, unkeyable], rec, plan);

    expect(groups).toHaveLength(1);
    expect(groups[0]?.pattern).toBe(safeMaskedMatch(RAW_STRIPE));
    expect(groups.every((g) => g.pattern !== safeMaskedMatch(RAW_AWS))).toBe(true);
  });

  it('marks only the ids the writeback resolves on a duplicate-category verdict (first occurrence wins)', () => {
    // A poisoned/duplicate model verdict lists the same category twice. The
    // writeback consumes the FIRST occurrence and drops the duplicate, so it
    // resolves suppressions from fpIds ['0'] only. The deriver must not mark '1'
    // as a false positive the writeback never resolved.
    const a = hit({ id: '0', rawMatch: RAW_AWS, valueFingerprint: 'ab'.repeat(32) });
    const b = hit({ id: '1', rawMatch: RAW_AWS, valueFingerprint: 'cd'.repeat(32) });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'first occurrence: marks hit 0',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'duplicate occurrence: marks hit 1',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['1'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([a, b], rec);

    const groups = deriveFalsePositivePatterns([a, b], rec, plan);

    expect(groups).toHaveLength(1);
    const g = groups[0];
    if (g === undefined) throw new Error('expected one group');
    // Only the first-occurrence mark ('0') is counted and keyed; the dropped
    // duplicate's mark ('1') contributes nothing.
    expect(g.count).toBe(1);
    expect(g.values).toEqual([
      {
        ruleId: 'secrets/aws-access-key',
        category: 'secret',
        valueFingerprint: 'ab'.repeat(32),
        keyVersion: 1,
      },
    ]);
  });

  it('carries each hit’s OWN category when a masked token collides across categories', () => {
    // Two rawMatch values from different DetectionCategories, both short enough
    // (<=5 chars) that maskMatch's rule 1 masks them identically to '***' — a
    // real masked-token collision, not a contrived shared string. The derived
    // group must carry each value's own category, never a single group-level one.
    const secretHit = hit({
      id: '0',
      category: 'secret',
      rawMatch: 'ab12',
      context: 'token=ab12',
      valueFingerprint: 'ab'.repeat(32),
    });
    const piiHit = hit({
      id: '1',
      category: 'pii',
      ruleId: 'pii/short-code',
      rawMatch: 'xy99',
      context: 'ssn=xy99',
      valueFingerprint: 'cd'.repeat(32),
    });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'canonical fixture keys, marked as false positives',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
        {
          category: 'pii',
          action: 'warn',
          reasoning: 'canonical fixture values, marked as false positives',
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['1'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([secretHit, piiHit], rec);

    const groups = deriveFalsePositivePatterns([secretHit, piiHit], rec, plan);

    expect(groups).toHaveLength(1);
    const g = groups[0];
    if (g === undefined) throw new Error('expected one collision group');
    expect(g.pattern).toBe('***');
    expect(g.count).toBe(2);
    const byFingerprint = new Map(g.values.map((v) => [v.valueFingerprint, v.category]));
    expect(byFingerprint.get('ab'.repeat(32))).toBe('secret');
    expect(byFingerprint.get('cd'.repeat(32))).toBe('pii');
    expect(FalsePositivePatternGroup.safeParse(g).success).toBe(true);
  });

  it('contributes nothing for a category the plan distrusted (reasoning echoed a raw value)', () => {
    const a = hit({ id: '0', rawMatch: RAW_STRIPE, context: `token=${RAW_STRIPE}` });
    const rec: TriageRecommendation = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          // reasoning that leaks the raw value → the whole category is dropped
          reasoning: `the key ${RAW_STRIPE} is a false positive`,
          genuineCount: 0,
          fpCount: 1,
          fpIds: ['0'],
        },
      ],
      notes: 'looks routine',
    };
    const plan = planTriageWriteback([a], rec);
    expect(plan.posture.secret).toBeUndefined();

    expect(deriveFalsePositivePatterns([a], rec, plan)).toEqual([]);
  });
});
