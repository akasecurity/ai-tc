import { describe, expect, it } from 'vitest';

import { TriageCategoryRec, TriageHit, TriagePolicy, TriageRecommendation } from './triage.ts';

const validHit = {
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A******************E',
  rawMatch: 'AKIAIOSFODNN7EXAMPLE',
  context: 'here is a key AKIAIOSFODNN7EXAMPLE in the transcript',
  confidence: 0.9,
};

describe('TriageHit', () => {
  it('parses a well-formed hit', () => {
    expect(TriageHit.safeParse(validHit).success).toBe(true);
  });

  it('rejects a hit missing rawMatch', () => {
    const { rawMatch, ...rest } = validHit;
    void rawMatch;
    expect(TriageHit.safeParse(rest).success).toBe(false);
  });

  it('rejects a mis-cased or pluralized category', () => {
    expect(TriageHit.safeParse({ ...validHit, category: 'secrets' }).success).toBe(false);
    expect(TriageHit.safeParse({ ...validHit, category: 'PII' }).success).toBe(false);
  });

  it('rejects an unknown severity', () => {
    expect(TriageHit.safeParse({ ...validHit, severity: 'urgent' }).success).toBe(false);
  });

  it('rejects confidence outside [0,1]', () => {
    expect(TriageHit.safeParse({ ...validHit, confidence: 1.5 }).success).toBe(false);
    expect(TriageHit.safeParse({ ...validHit, confidence: -0.1 }).success).toBe(false);
  });

  it('parses with id/valueFingerprint/keyVersion present, and with them absent', () => {
    expect(
      TriageHit.safeParse({ ...validHit, id: '0', valueFingerprint: 'fp1', keyVersion: 1 }).success,
    ).toBe(true);
    expect(TriageHit.safeParse(validHit).success).toBe(true);
  });
});

describe('TriagePolicy', () => {
  it('accepts every built-in policy id', () => {
    for (const id of ['monitor', 'warn', 'redact', 'block']) {
      expect(TriagePolicy.safeParse(id).success).toBe(true);
    }
  });

  it('rejects a runtime-internal action', () => {
    expect(TriagePolicy.safeParse('log').success).toBe(false);
    expect(TriagePolicy.safeParse('allow').success).toBe(false);
  });
});

describe('TriageCategoryRec', () => {
  const validRec = {
    category: 'secret',
    action: 'block',
    reasoning: 'consistently high-confidence AWS key matches',
    genuineCount: 2,
    fpCount: 1,
    fpIds: ['0'],
  };

  it('parses a well-formed record', () => {
    expect(TriageCategoryRec.safeParse(validRec).success).toBe(true);
  });

  it('rejects a bad category', () => {
    expect(TriageCategoryRec.safeParse({ ...validRec, category: 'secrets' }).success).toBe(false);
  });

  it('rejects a non-integer or negative count', () => {
    expect(TriageCategoryRec.safeParse({ ...validRec, genuineCount: 1.5 }).success).toBe(false);
    expect(TriageCategoryRec.safeParse({ ...validRec, fpCount: -1 }).success).toBe(false);
  });

  it('rejects a non-string-array fpIds', () => {
    expect(TriageCategoryRec.safeParse({ ...validRec, fpIds: [1, 2] }).success).toBe(false);
  });
});

describe('TriageRecommendation', () => {
  it('rejects an out-of-palette action inside perCategory', () => {
    const rec = {
      perCategory: [
        {
          category: 'secret',
          action: 'allow',
          reasoning: 'n/a',
          genuineCount: 0,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: '',
    };
    expect(TriageRecommendation.safeParse(rec).success).toBe(false);
  });

  it('accepts an in-palette action', () => {
    const rec = {
      perCategory: [
        {
          category: 'secret',
          action: 'warn',
          reasoning: 'n/a',
          genuineCount: 0,
          fpCount: 0,
          fpIds: [],
        },
      ],
      notes: '',
    };
    expect(TriageRecommendation.safeParse(rec).success).toBe(true);
  });
});
