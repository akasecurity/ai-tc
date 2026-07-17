import { CalibrationFrame, type CalibrationPreview } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { frameCalibration } from '../src/calibration.ts';

// A backfill + apply-suppressions preview with 161 findings of which 3 are surfaced
// (genuine live secret keys) and 158 are suppressed FPs. Every count is carried in
// from the preview breakdown — nothing is hardcoded in the module under test.
const preview: CalibrationPreview = {
  categories: [
    { category: 'secret', genuineCount: 3, fpCount: 0, egress: false },
    { category: 'pii', genuineCount: 0, fpCount: 100, egress: false },
    { category: 'code_context', genuineCount: 0, fpCount: 50, egress: false },
    { category: 'config', genuineCount: 0, fpCount: 8, egress: false },
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

describe('frameCalibration', () => {
  it('reports 161 notifications, 3 important, 158 routine from the preview', () => {
    const { frame } = frameCalibration(preview);
    expect(frame.counts).toEqual({ total: 161, important: 3, routine: 158 });
  });

  it('emits a valid CalibrationFrame shape', () => {
    const { frame } = frameCalibration(preview);
    expect(CalibrationFrame.safeParse(frame).success).toBe(true);
  });

  it("'important' equals the surfaced count and 'routine' equals the suppressed count", () => {
    const surfaced = preview.categories.reduce((n, c) => n + c.genuineCount, 0);
    const suppressed = preview.categories.reduce((n, c) => n + c.fpCount, 0);
    const { frame } = frameCalibration(preview);
    expect(frame.counts.important).toBe(surfaced);
    expect(frame.counts.routine).toBe(suppressed);
    // Emitter-enforced sum: total is exactly important + routine, no third source.
    expect(frame.counts.total).toBe(frame.counts.important + frame.counts.routine);
  });

  it('partitions the surfaced and routine category lists', () => {
    const { frame } = frameCalibration(preview);
    expect(frame.surfacedCategories).toEqual(['secret']);
    expect(frame.routineCategories).toEqual(['pii', 'code_context', 'config']);
  });

  it('keeps a mixed category in both lists — its suppressed findings still count as routine', () => {
    const mixed: CalibrationPreview = {
      categories: [{ category: 'secret', genuineCount: 2, fpCount: 5, egress: false }],
      posture: preview.posture,
    };
    const { frame } = frameCalibration(mixed);
    expect(frame.surfacedCategories).toEqual(['secret']);
    expect(frame.routineCategories).toEqual(['secret']);
    expect(frame.counts).toEqual({ total: 7, important: 2, routine: 5 });
  });

  it('carries the egress-kind axis through into findingKinds', () => {
    const { frame } = frameCalibration(preview);
    expect(frame.findingKinds).toContainEqual({ category: 'secret', count: 3, egress: false });
    // Every finding kind carries the axis; none is dropped.
    expect(frame.findingKinds.every((k) => typeof k.egress === 'boolean')).toBe(true);
  });

  it("templates the 'Calibrated.' copy exactly over the preview values", () => {
    const { copy } = frameCalibration(preview);
    expect(copy).toBe(
      'Calibrated. 161 notifications, 3 important. 158 routine, 3 that matter (live keys)',
    );
  });

  it('templates over a different preview — the numbers follow the input', () => {
    const other: CalibrationPreview = {
      categories: [
        { category: 'secret', genuineCount: 2, fpCount: 0, egress: false },
        { category: 'pii', genuineCount: 0, fpCount: 8, egress: false },
      ],
      posture: preview.posture,
    };
    const { frame, copy } = frameCalibration(other);
    expect(frame.counts).toEqual({ total: 10, important: 2, routine: 8 });
    expect(copy).toBe(
      'Calibrated. 10 notifications, 2 important. 8 routine, 2 that matter (live keys)',
    );
    expect(copy).not.toContain('161');
  });

  it('omits the kind parenthetical entirely when nothing surfaced (all suppressed)', () => {
    const allSuppressed: CalibrationPreview = {
      categories: [
        { category: 'pii', genuineCount: 0, fpCount: 8, egress: false },
        { category: 'config', genuineCount: 0, fpCount: 2, egress: false },
      ],
      posture: preview.posture,
    };
    const { frame, copy } = frameCalibration(allSuppressed);
    expect(frame.surfacedCategories).toEqual([]);
    expect(frame.counts).toEqual({ total: 10, important: 0, routine: 10 });
    expect(copy).toBe('Calibrated. 10 notifications, 0 important. 10 routine, 0 that matter');
    // No dangling empty parenthetical.
    expect(copy).not.toContain('()');
    expect(copy).not.toContain('matter (');
  });

  it("derives the 'that matter (…)' kind from the surfaced categories, not a fixed label", () => {
    const piiSurfaced: CalibrationPreview = {
      categories: [
        { category: 'pii', genuineCount: 4, fpCount: 0, egress: false },
        { category: 'secret', genuineCount: 0, fpCount: 20, egress: false },
      ],
      posture: preview.posture,
    };
    const { copy } = frameCalibration(piiSurfaced);
    expect(copy).toBe(
      'Calibrated. 24 notifications, 4 important. 20 routine, 4 that matter (personal data)',
    );
    expect(copy).not.toContain('live keys');
  });
});
