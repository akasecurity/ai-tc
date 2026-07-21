/**
 * Store-read failure mid-wizard completes fail-open, proven end-to-end against
 * the REAL script chain.
 *
 * This is the app-level e2e leg the unit seams (test/triage/adapter.test.ts,
 * test/firstrun-core.test.ts) could not reach: it drives the shipped wizard
 * scripts in frame order, then makes the local store unreadable AFTER the
 * backfill has populated it and BEFORE the two store-reading steps run. The
 * calibration preview (its current-posture downgrade read) and the first-run
 * card (its stats + posture read) must each substitute the honest
 * store-unavailable note, never throw out of the script (exit 0), and still
 * reach completion — the calibration headline still carries the real
 * plan-derived count, never a fabricated or zeroed one. The single corruption
 * is left in place across both steps, so the fault genuinely persists rather
 * than being papered over between reads.
 *
 * The found-nothing / empty-store copy is a distinct path and is not exercised
 * here.
 */
import { CalibrationFrame, DetectionCategory } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { STORE_UNAVAILABLE_NOTE } from '../../src/render.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { ROUTINE_KEY, SetupJourney, SURFACED_KEY } from './harness.ts';

describe('store-read failure mid-wizard completes fail-open, end-to-end', () => {
  let journey: SetupJourney;
  let preview: { stdout: string; stderr: string; status: number };
  let firstRun: { stdout: string; stderr: string; status: number };

  beforeAll(() => {
    journey = new SetupJourney();
    journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');

    // A real backfill populates the store from the seeded history.
    const triage = journey.backfillTriage().stdout;

    // The store now goes unreadable mid-wizard (missing/corrupt/locked db). The
    // single corruption stays in place for BOTH store-reading steps below.
    journey.corruptStore();

    // The calibration preview's only store read (the downgrade view)
    // hits the unreadable store.
    preview = journey.applyPreview(triage);

    // The first-run card's stats + posture reads hit the same
    // unreadable store.
    firstRun = journey.firstRun(1);
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('the calibration preview substitutes the fail-open note, exits clean, and renders its full frame past the fault', () => {
    // No error escaped the calibration script — it exited 0 with the note, not a throw.
    expect(preview.status).toBe(0);
    expect(preview.stdout).toContain(STORE_UNAVAILABLE_NOTE);

    // The real calibrated headline still renders from the plan (two seeded keys:
    // one surfaced, one routine FP) — a store-read failure never zeroes or
    // fabricates the count.
    expect(preview.stdout).toContain(
      "I went through Claude's recent work — 2 detections, 1 result worth a look. (live keys)",
    );

    // The step did not stop at the note — it continued past the failed store read
    // and rendered the COMPLETE frame downstream of it: the recommended posture
    // (every category) and the machine-readable calibration frame JSON, whose
    // counts are the real plan-derived ones (not zeroed or fabricated).
    for (const category of DetectionCategory.options) {
      expect(preview.stdout).toContain(category);
    }
    const frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));
    expect(frame.counts).toEqual({ total: 2, important: 1, routine: 1 });

    // The step reached completion: the plan was still persisted for the confirm.
    expect(preview.stdout).toContain('Plan saved to:');
  });

  it('the wizard reaches its terminal first-run frame fail-open, degrading cleanly without fabricating an install summary', () => {
    // The terminal step ran as a distinct execution AFTER the preview fault (so the
    // first fault never aborted the run) and degraded cleanly: exit 0, the honest
    // note, and nothing on stderr.
    expect(firstRun.status).toBe(0);
    expect(firstRun.stderr).toBe('');
    expect(firstRun.stdout).toContain(STORE_UNAVAILABLE_NOTE);

    // It never papered over the unreadable store with a fabricated install card:
    // neither the scan-path nor the floor-path heading appears, so the note
    // stands in for the whole frame rather than a zeroed-out summary.
    expect(firstRun.stdout).not.toContain("You're all set");
  });

  it('the fail-open notes never leak a raw detected value', () => {
    for (const out of [preview.stdout, firstRun.stdout]) {
      expect(out).not.toContain(SURFACED_KEY);
      expect(out).not.toContain(ROUTINE_KEY);
    }
  });
});
