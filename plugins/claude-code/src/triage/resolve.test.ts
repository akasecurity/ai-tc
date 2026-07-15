import type { TriageCategoryRec, TriageRecommendation } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { JoinEntry } from './join-file.ts';
import { resolveSuppressions } from './resolve.ts';

const FP = 'ab'.repeat(32);

const joinEntry = (over: Partial<JoinEntry> = {}): JoinEntry => ({
  id: '0',
  ruleId: 'core-secret/aws',
  category: 'secret',
  valueFingerprint: FP,
  keyVersion: 1,
  maskedMatch: 'A***Z',
  maskedContext: 'export KEY=A***Z # prod',
  ...over,
});

const cat = (over: Partial<TriageCategoryRec> = {}): TriageCategoryRec => ({
  category: 'secret',
  action: 'warn',
  reasoning: 'placeholder',
  genuineCount: 0,
  fpCount: 1,
  fpIds: ['0'],
  ...over,
});

const rec = (cats: TriageCategoryRec[]): TriageRecommendation => ({
  perCategory: cats,
  notes: '',
});

describe('resolveSuppressions', () => {
  it('maps a consistent category to one SuppressionEntry per fpId', () => {
    const { entries, skipped } = resolveSuppressions(rec([cat()]), [joinEntry()]);
    expect(skipped).toEqual([]);
    expect(entries).toEqual([
      {
        ruleId: 'core-secret/aws',
        category: 'secret',
        valueFingerprint: FP,
        keyVersion: 1,
        maskedValue: 'A***Z',
        justification: 'placeholder',
      },
    ]);
  });

  it('RELAX: on fpCount !== fpIds.length, resolves the mappable ids and notes the discrepancy', () => {
    // The whole category is no longer voided on a miscount (the binding human gate
    // is the fail-secure guard now). The one resolvable id is suppressed and the
    // discrepancy is recorded so the preview can surface "model reported N, M resolved".
    const { entries, skipped } = resolveSuppressions(rec([cat({ fpCount: 2, fpIds: ['0'] })]), [
      joinEntry(),
    ]);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.valueFingerprint).toBe(FP);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]?.category).toBe('secret');
    expect(skipped[0]?.reason).toMatch(/discrepancy/i);
    expect(skipped[0]?.reason).toMatch(/1 resolved/);
  });

  it('RELAX: an unresolvable id inside a miscounted category is still dropped individually', () => {
    // fpCount 3 but two ids listed (a miscount), and only one id maps to the join:
    // the mapped one resolves, the missing one drops, and the discrepancy is noted.
    const { entries, skipped } = resolveSuppressions(
      rec([cat({ fpCount: 3, fpIds: ['0', '404'] })]),
      [joinEntry()],
    );
    expect(entries).toHaveLength(1);
    expect(skipped.some((s) => /not found/i.test(s.reason))).toBe(true);
    expect(skipped.some((s) => /discrepancy/i.test(s.reason))).toBe(true);
  });

  it('drops an fpId whose join entry has no valueFingerprint', () => {
    const noFp: JoinEntry = {
      id: '0',
      ruleId: 'core-secret/aws',
      category: 'secret',
      maskedMatch: 'A***Z',
      maskedContext: 'export KEY=A***Z # prod',
    };
    const { entries, skipped } = resolveSuppressions(rec([cat()]), [noFp]);
    expect(entries).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]?.reason).toMatch(/fingerprint/i);
  });

  it('does not crash when an fpId is missing from the join', () => {
    const { entries, skipped } = resolveSuppressions(rec([cat({ fpIds: ['404'] })]), [joinEntry()]);
    expect(entries).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]?.reason).toMatch(/not found|missing/i);
  });
});
