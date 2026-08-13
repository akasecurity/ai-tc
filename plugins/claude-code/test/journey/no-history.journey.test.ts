/**
 * The no-history vs scan-clean empty-state distinction, proven end-to-end over
 * the REAL backfill producer -> apply-suppressions consumer script chain.
 *
 * The unit seams (test/calibration.test.ts, test/triage/adapter.test.ts) prove
 * the copy and the adapter branch against hand-built inputs. This binds the two
 * shipped scripts: a real backfill over a genuinely empty history set must emit
 * the no-history signal, and the shipped apply-suppressions preview must render
 * the no-history copy through it — while a backfill over a history set that was
 * examined and surfaced nothing still emits scan-clean and renders the scan-clean
 * copy. The signal crosses backfill.js -> apply-suppressions.js, so the observable
 * cannot ship dead behind a hand-built adapter-only input.
 */
import { CalibrationFrame } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { SetupJourney } from './harness.ts';

const NO_HISTORY_COPY = 'Nothing to learn from yet';
const SCAN_CLEAN_COPY = 'nothing needs your attention';

describe('empty-history backfill renders the no-history calibration copy end-to-end', () => {
  let journey: SetupJourney;
  let triageStream: string;
  let preview: { stdout: string; stderr: string; status: number };

  beforeAll(() => {
    journey = new SetupJourney();
    // No transcript seeded: a genuinely empty history set (nothing to calibrate from).
    journey.intro();
    journey.onboardHistorical('full');
    triageStream = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triageStream);
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('the producer emits the no-history signal over an empty history set', () => {
    // The stream carries only the sentinel: zero hits, complete:no-history.
    expect(triageStream.trim()).toBe(
      JSON.stringify({ done: true, count: 0, status: 'complete:no-history' }),
    );
  });

  it('the shipped preview renders the no-history copy, not scan-clean', () => {
    expect(preview.status).toBe(0);
    expect(preview.stdout).toContain(NO_HISTORY_COPY);
    expect(preview.stdout).not.toContain(SCAN_CLEAN_COPY);
    expect(preview.stdout).not.toContain('No triage hits to review');
    const frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
  });
});

describe('scanned-clean-with-history backfill still renders the scan-clean copy end-to-end', () => {
  let journey: SetupJourney;
  let triageStream: string;
  let preview: { stdout: string; stderr: string; status: number };

  beforeAll(() => {
    journey = new SetupJourney();
    // History exists and is examined, but nothing surfaces: scan-clean, not no-history.
    journey.seedCleanTranscript();
    journey.intro();
    journey.onboardHistorical('full');
    triageStream = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triageStream);
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('the producer emits the scan-clean signal when history was examined', () => {
    expect(triageStream.trim()).toBe(JSON.stringify({ done: true, count: 0, status: 'complete' }));
  });

  it('the shipped preview renders the scan-clean copy, not no-history', () => {
    expect(preview.status).toBe(0);
    expect(preview.stdout).toContain(SCAN_CLEAN_COPY);
    expect(preview.stdout).not.toContain(NO_HISTORY_COPY);
    expect(preview.stdout).not.toContain('No triage hits to review');
    const frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
  });
});
