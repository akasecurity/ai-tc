import { describe, expect, it } from 'vitest';

import {
  CalibrationCounts,
  CalibrationFindingKind,
  CalibrationFrame,
} from '../../src/zod/setup-frame.ts';

// A populated example frame: 161 total notifications, 3 important (surfaced),
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
