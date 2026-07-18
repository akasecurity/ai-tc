import {
  CalibrationFrame,
  type CalibrationPreview,
  severityFloorPosture,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { frameCalibration, frameEmptyState } from '../src/calibration.ts';
import { renderPostureGrid, renderRecommendedPosture } from '../src/render.ts';

const HONEST_POSITIVE_LINE = "Good news: nothing looks like it's actually gone wrong recently.";

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
      'Calibrated. 161 notifications, 3 important. 158 routine, 3 that matter (live keys)\n' +
        HONEST_POSITIVE_LINE,
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
      'Calibrated. 10 notifications, 2 important. 8 routine, 2 that matter (live keys)\n' +
        HONEST_POSITIVE_LINE,
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
    expect(copy).toBe(
      'Calibrated. 10 notifications, 0 important. 10 routine, 0 that matter\n' +
        HONEST_POSITIVE_LINE,
    );
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
      'Calibrated. 24 notifications, 4 important. 20 routine, 4 that matter (personal data)\n' +
        HONEST_POSITIVE_LINE,
    );
    expect(copy).not.toContain('live keys');
  });

  it('renders the honest-positive line when no surfaced finding kind is egress', () => {
    const atRestLiveKeys: CalibrationPreview = {
      categories: [
        { category: 'secret', genuineCount: 3, fpCount: 0, egress: false },
        { category: 'pii', genuineCount: 0, fpCount: 40, egress: false },
      ],
      posture: preview.posture,
    };
    const { frame, copy } = frameCalibration(atRestLiveKeys);
    // The gate reads the frame's egress axis: no finding kind is an egress kind.
    expect(frame.findingKinds.some((k) => k.egress)).toBe(false);
    expect(copy).toContain(HONEST_POSITIVE_LINE);
    // Rendered alongside the surfaced at-rest live-key headline, not instead of it.
    expect(copy).toContain('that matter (live keys)');
  });

  it('suppresses the honest-positive line the moment a finding kind is egress', () => {
    // Same surfaced live keys as above; flipping one kind's egress axis is the only change.
    const withEgress: CalibrationPreview = {
      categories: [
        { category: 'secret', genuineCount: 3, fpCount: 0, egress: false },
        { category: 'pii', genuineCount: 0, fpCount: 40, egress: true },
      ],
      posture: preview.posture,
    };
    const { frame, copy } = frameCalibration(withEgress);
    expect(frame.findingKinds.some((k) => k.egress)).toBe(true);
    expect(copy).not.toContain(HONEST_POSITIVE_LINE);
  });
});

describe('frameEmptyState', () => {
  const posture = severityFloorPosture();

  // The exact per-cause headlines, spelled out here (not sourced from the module)
  // so the test pins the shipped copy rather than mirroring the implementation.
  const SCAN_CLEAN_HEADLINE =
    "Calibrated. I looked at Claude's recent activity — nothing needs your attention. You're starting clean; here's the posture I'd recommend:";
  const NO_HISTORY_HEADLINE =
    "Nothing to calibrate from yet — Claude hasn't left activity on this machine. Each pack starts at a conservative default:";

  it('scan-ran-clean renders the exact clean copy over the recommended posture', () => {
    const { copy } = frameEmptyState('scan-clean', posture);
    expect(copy).toBe(`${SCAN_CLEAN_HEADLINE}\n${renderRecommendedPosture(posture)}`);
  });

  it('no-history renders the exact start-light copy over the 0.3b table', () => {
    const { copy } = frameEmptyState('no-history', posture);
    expect(copy).toBe(`${NO_HISTORY_HEADLINE}\n${renderPostureGrid(posture)}`);
  });

  it('the two empty-state copies are distinct and each states why it is empty', () => {
    const clean = frameEmptyState('scan-clean', posture).copy;
    const noHistory = frameEmptyState('no-history', posture).copy;
    expect(clean).not.toBe(noHistory);
    // scan-ran-clean states a scan looked and found nothing.
    expect(clean).toContain("I looked at Claude's recent activity");
    // no-history states there is nothing on this machine to calibrate from.
    expect(noHistory).toContain("Claude hasn't left activity on this machine");
  });

  it('never renders a fabricated count — no "0 notifications" theater', () => {
    for (const cause of ['scan-clean', 'no-history'] as const) {
      const { copy } = frameEmptyState(cause, posture);
      expect(copy).not.toMatch(/\d+\s+notifications/);
    }
  });

  it('emits a valid zero-count CalibrationFrame', () => {
    for (const cause of ['scan-clean', 'no-history'] as const) {
      const { frame } = frameEmptyState(cause, posture);
      expect(CalibrationFrame.safeParse(frame).success).toBe(true);
      expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
      expect(frame.surfacedCategories).toEqual([]);
      expect(frame.routineCategories).toEqual([]);
      expect(frame.findingKinds).toEqual([]);
      expect(frame.posture).toEqual(posture);
    }
  });
});
