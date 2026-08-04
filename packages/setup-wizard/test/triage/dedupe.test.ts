import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { dedupeForJudge } from '../../src/triage/dedupe.ts';

const hit = (o: Partial<TriageHit>): TriageHit => ({
  ruleId: 'r',
  category: 'secret',
  severity: 'high',
  maskedMatch: 'm',
  rawMatch: 'raw',
  context: 'c',
  confidence: 0.9,
  ...o,
});

describe('dedupeForJudge', () => {
  it('collapses repeats by (ruleId,valueFingerprint), keeps distinct + fingerprint-less', () => {
    const out = dedupeForJudge([
      hit({ id: '0', valueFingerprint: 'fp1' }),
      hit({ id: '1', valueFingerprint: 'fp1' }),
      hit({ id: '2', valueFingerprint: 'fp2' }),
      hit({ id: '3', valueFingerprint: undefined }),
      hit({ id: '4', valueFingerprint: undefined }),
    ]);
    expect(out.map((h) => h.id)).toEqual(['0', '2', '3', '4']);
  });
});
