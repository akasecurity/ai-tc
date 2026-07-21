import { describe, expect, it } from 'vitest';

import { chunkForJudge, mergeRecommendations } from '../../src/triage/merge.ts';

describe('mergeRecommendations', () => {
  it('merges per category: sums, unions ids, strictest action wins', () => {
    const m = mergeRecommendations([
      {
        perCategory: [
          {
            category: 'secret',
            action: 'warn',
            reasoning: 'a',
            genuineCount: 1,
            fpCount: 1,
            fpIds: ['1'],
          },
        ],
        notes: 'n1',
      },
      {
        perCategory: [
          {
            category: 'secret',
            action: 'redact',
            reasoning: 'b',
            genuineCount: 2,
            fpCount: 0,
            fpIds: [],
          },
          {
            category: 'pii',
            action: 'warn',
            reasoning: 'c',
            genuineCount: 1,
            fpCount: 0,
            fpIds: [],
          },
        ],
        notes: 'n2',
      },
    ]);
    const sec = m.perCategory.find((c) => c.category === 'secret');
    if (sec === undefined) throw new Error('expected a merged secret category');
    expect([sec.genuineCount, sec.fpCount, sec.action, sec.fpIds]).toEqual([3, 1, 'redact', ['1']]);
    expect(m.notes).toBe('n1\nn2');
  });
});

describe('chunkForJudge', () => {
  it('chunkForJudge returns a single chunk under the cap', () => {
    expect(
      chunkForJudge(
        [
          {
            ruleId: 'r',
            category: 'secret',
            severity: 'high',
            maskedMatch: 'm',
            rawMatch: 'raw',
            context: 'c',
            confidence: 0.9,
          },
        ],
        262_144,
      ),
    ).toHaveLength(1);
  });
});
