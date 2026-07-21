import { describe, expect, it } from 'vitest';

import {
  CalibrationCounts,
  CalibrationFindingKind,
  CalibrationFrame,
  FalsePositivePatternGroup,
  FirstRunCalibration,
  SetupHandoffOffer,
} from '../../src/zod/setup-frame.ts';

// A populated example frame: 161 total detections, 3 important (surfaced),
// 158 routine (suppressed); the surfaced findings are at-rest live secret keys
// (no egress-kind evidence).
const populatedFrame = {
  counts: { total: 161, important: 3, routine: 158 },
  routineCategories: ['pii', 'code_context', 'config'],
  surfacedCategories: ['secret'],
  findingKinds: [
    { category: 'secret', count: 3, egress: false },
    { category: 'pii', count: 12, egress: false },
  ],
  posture: {
    secret: 'warn',
    pii: 'warn',
    financial: 'warn',
    phi: 'warn',
    code_flaw: 'warn',
    custom: 'warn',
    code_context: 'monitor',
    config: 'monitor',
  },
};

describe('CalibrationCounts', () => {
  it('parses a well-formed count triple', () => {
    expect(CalibrationCounts.safeParse({ total: 161, important: 3, routine: 158 }).success).toBe(
      true,
    );
  });

  it('accepts a fully-zero count triple (never rendered as theater, but valid)', () => {
    expect(CalibrationCounts.safeParse({ total: 0, important: 0, routine: 0 }).success).toBe(true);
  });

  it('rejects a non-integer or negative count', () => {
    expect(CalibrationCounts.safeParse({ total: 1.5, important: 0, routine: 0 }).success).toBe(
      false,
    );
    expect(CalibrationCounts.safeParse({ total: 0, important: -1, routine: 0 }).success).toBe(
      false,
    );
  });

  it('rejects a missing member', () => {
    expect(CalibrationCounts.safeParse({ total: 1, important: 1 }).success).toBe(false);
  });

  it('accepts counts whose total equals important + routine', () => {
    expect(CalibrationCounts.safeParse({ total: 161, important: 3, routine: 158 }).success).toBe(
      true,
    );
  });

  it('rejects counts whose total does not equal important + routine', () => {
    expect(CalibrationCounts.safeParse({ total: 160, important: 3, routine: 158 }).success).toBe(
      false,
    );
  });
});

describe('CalibrationFindingKind', () => {
  it('parses a kind carrying the egress axis', () => {
    expect(
      CalibrationFindingKind.safeParse({ category: 'secret', count: 3, egress: false }).success,
    ).toBe(true);
    expect(
      CalibrationFindingKind.safeParse({ category: 'secret', count: 1, egress: true }).success,
    ).toBe(true);
  });

  it('rejects a missing egress axis', () => {
    expect(CalibrationFindingKind.safeParse({ category: 'secret', count: 3 }).success).toBe(false);
  });

  it('rejects a non-boolean egress axis', () => {
    expect(
      CalibrationFindingKind.safeParse({ category: 'secret', count: 3, egress: 'no' }).success,
    ).toBe(false);
  });

  it('rejects an unknown or mis-cased category', () => {
    expect(
      CalibrationFindingKind.safeParse({ category: 'secrets', count: 3, egress: false }).success,
    ).toBe(false);
  });
});

describe('CalibrationFrame', () => {
  it('parses a populated frame (161 total / 3 important / 158 routine, surfaced secret)', () => {
    expect(CalibrationFrame.safeParse(populatedFrame).success).toBe(true);
  });

  it('rejects a frame whose surfaced category list is not a DetectionCategory', () => {
    expect(
      CalibrationFrame.safeParse({ ...populatedFrame, surfacedCategories: ['secrets'] }).success,
    ).toBe(false);
  });

  it('rejects a frame whose posture map assigns a non-built-in policy id', () => {
    expect(
      CalibrationFrame.safeParse({
        ...populatedFrame,
        posture: { ...populatedFrame.posture, secret: 'allow' },
      }).success,
    ).toBe(false);
  });

  it('rejects a frame whose posture map omits a category', () => {
    const { config, ...partial } = populatedFrame.posture;
    void config;
    expect(CalibrationFrame.safeParse({ ...populatedFrame, posture: partial }).success).toBe(false);
  });

  it('rejects a frame with a malformed finding kind', () => {
    expect(
      CalibrationFrame.safeParse({
        ...populatedFrame,
        findingKinds: [{ category: 'secret', count: -1, egress: false }],
      }).success,
    ).toBe(false);
  });

  it('rejects a frame missing a required top-level field', () => {
    const { counts, ...rest } = populatedFrame;
    void counts;
    expect(CalibrationFrame.safeParse(rest).success).toBe(false);
  });
});

describe('CalibrationFrame masked per-finding summaries (additive)', () => {
  const maskedFindings = [
    {
      provider: 'stripe',
      maskedToken: 'sk_live_…4f2c',
      where: {
        filePath: '~/.claude/projects/acme/transcript.jsonl',
        span: { start: 120, end: 148 },
      },
      state: 'still-valid',
    },
  ];

  it('parses a frame WITHOUT the masked-findings field (additivity — existing frames unchanged)', () => {
    expect('maskedFindings' in populatedFrame).toBe(false);
    expect(CalibrationFrame.safeParse(populatedFrame).success).toBe(true);
  });

  it('parses a frame WITH a masked-findings array', () => {
    expect(CalibrationFrame.safeParse({ ...populatedFrame, maskedFindings }).success).toBe(true);
  });

  it('rejects a frame whose masked-findings entry carries a raw-looking secret field', () => {
    expect(
      CalibrationFrame.safeParse({
        ...populatedFrame,
        maskedFindings: [{ ...maskedFindings[0], rawToken: 'sk_live_EXAMPLE0000000000000000' }],
      }).success,
    ).toBe(false);
  });
});

describe('CalibrationFrame masked false-positive pattern signal (additive)', () => {
  const falsePositivePatterns = [
    {
      pattern: 'test_sk_live_placeholder',
      count: 12,
      values: [
        {
          ruleId: 'secret-stripe-live-key',
          category: 'secret',
          valueFingerprint: 'fp-aaa',
          keyVersion: 1,
        },
      ],
    },
  ];

  it('parses a frame WITHOUT the false-positive-patterns field (additivity — existing frames unchanged)', () => {
    expect('falsePositivePatterns' in populatedFrame).toBe(false);
    expect(CalibrationFrame.safeParse(populatedFrame).success).toBe(true);
  });

  it('parses and round-trips a frame WITH a well-formed false-positive-patterns group', () => {
    const result = CalibrationFrame.safeParse({ ...populatedFrame, falsePositivePatterns });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.falsePositivePatterns).toEqual(falsePositivePatterns);
    }
  });

  it('parses a group whose values carry more than one distinct valueFingerprint (masked-token collision)', () => {
    const collisionGroup = [
      {
        pattern: 'test_sk_live_placeholder',
        count: 2,
        values: [
          {
            ruleId: 'secret-stripe-live-key',
            category: 'secret',
            valueFingerprint: 'fp-aaa',
            keyVersion: 1,
          },
          {
            ruleId: 'secret-stripe-live-key',
            category: 'pii',
            valueFingerprint: 'fp-bbb',
            keyVersion: 1,
          },
        ],
      },
    ];
    expect(
      CalibrationFrame.safeParse({ ...populatedFrame, falsePositivePatterns: collisionGroup })
        .success,
    ).toBe(true);
  });

  it('rejects a group whose value entry is missing valueFingerprint', () => {
    const malformed = [
      {
        pattern: 'test_sk_live_placeholder',
        count: 1,
        values: [{ ruleId: 'secret-stripe-live-key', category: 'secret', keyVersion: 1 }],
      },
    ];
    expect(
      CalibrationFrame.safeParse({ ...populatedFrame, falsePositivePatterns: malformed }).success,
    ).toBe(false);
  });

  it('rejects a group with an empty values array', () => {
    const malformed = [{ pattern: 'test_sk_live_placeholder', count: 0, values: [] }];
    expect(
      CalibrationFrame.safeParse({ ...populatedFrame, falsePositivePatterns: malformed }).success,
    ).toBe(false);
  });

  it('rejects a group with a negative count', () => {
    const malformed = [
      {
        pattern: 'test_sk_live_placeholder',
        count: -1,
        values: [
          {
            ruleId: 'secret-stripe-live-key',
            category: 'secret',
            valueFingerprint: 'fp-aaa',
            keyVersion: 1,
          },
        ],
      },
    ];
    expect(
      CalibrationFrame.safeParse({ ...populatedFrame, falsePositivePatterns: malformed }).success,
    ).toBe(false);
  });

  it('FalsePositivePatternGroup rejects a negative keyVersion', () => {
    expect(
      FalsePositivePatternGroup.safeParse({
        pattern: 'test_sk_live_placeholder',
        count: 1,
        values: [
          {
            ruleId: 'secret-stripe-live-key',
            category: 'secret',
            valueFingerprint: 'fp-aaa',
            keyVersion: -1,
          },
        ],
      }).success,
    ).toBe(false);
  });
});

describe('SetupHandoffOffer', () => {
  const openDashboard = { id: 'open-dashboard', label: 'Open dashboard' };
  const notNow = { id: 'not-now', label: 'Not now' };

  it('parses the fixed two-entry offer (open-dashboard then not-now)', () => {
    expect(
      SetupHandoffOffer.safeParse({ worthALook: 3, options: [openDashboard, notNow] }).success,
    ).toBe(true);
  });

  it('rejects a dropped option (only one entry)', () => {
    expect(SetupHandoffOffer.safeParse({ worthALook: 3, options: [openDashboard] }).success).toBe(
      false,
    );
  });

  it('rejects reordered options (not-now before open-dashboard)', () => {
    expect(
      SetupHandoffOffer.safeParse({ worthALook: 3, options: [notNow, openDashboard] }).success,
    ).toBe(false);
  });

  it('rejects an extra option beyond the fixed tuple', () => {
    expect(
      SetupHandoffOffer.safeParse({
        worthALook: 3,
        options: [openDashboard, notNow, { id: 'not-now', label: 'Later' }],
      }).success,
    ).toBe(false);
  });
});

describe('FirstRunCalibration', () => {
  it('accepts scan and floor', () => {
    expect(FirstRunCalibration.safeParse('scan').success).toBe(true);
    expect(FirstRunCalibration.safeParse('floor').success).toBe(true);
  });

  it('rejects any other value', () => {
    expect(FirstRunCalibration.safeParse('calibrated').success).toBe(false);
    expect(FirstRunCalibration.safeParse('').success).toBe(false);
  });
});
