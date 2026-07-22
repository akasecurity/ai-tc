/**
 * The FP-signal grounding leg, proven end-to-end against the REAL
 * script chain: the built apply-suppressions preview emits the masked
 * false-positive pattern signal into the calibration frame
 * JSON, and the prompt-contract checker (`checkFpSignalContract`) grounds
 * a named pattern/count against it — over a REAL captured frame, never a
 * hand-assembled one.
 *
 * This owns no behavior — the producer (src/triage/false-positive-patterns.ts)
 * and the checker (eval/prompt-contract.ts) do — it just drives the shipped
 * backfill -> apply-suppressions chain in wizard order and asserts the emitted
 * frame JSON and the checker's grounding over it. The exception-write-through,
 * decline, collision, and duration-picker legs are proven by the writer's own
 * unit and real-store tests; this file proves only the FP-signal producer ->
 * checker leg plus its fail-open twin.
 */
import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import { CalibrationFrame } from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { checkFpSignalContract } from '../../eval/prompt-contract.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { REPEATED_FP_KEYS, SetupJourney } from './harness.ts';

// The one emitted group, asserted present by the caller first — extracted
// without a non-null assertion so an actually-missing group fails loud with a
// clear message instead of a bare TypeError.
function soleGroup(
  frame: CalibrationFrame,
): NonNullable<CalibrationFrame['falsePositivePatterns']>[number] {
  const groups = frame.falsePositivePatterns;
  if (groups?.length !== 1) {
    throw new Error('expected exactly one falsePositivePatterns group');
  }
  const [group] = groups;
  if (group === undefined) throw new Error('expected exactly one falsePositivePatterns group');
  return group;
}

describe('FP-pattern signal grounds end-to-end over a repeated-value false positive', () => {
  let journey: SetupJourney;
  let preview: { stdout: string; stderr: string; status: number };
  let frame: CalibrationFrame;

  beforeAll(() => {
    journey = new SetupJourney();
    journey.seedRepeatedFalsePositiveTranscript();

    journey.intro();
    journey.onboardHistorical('full');

    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage);
    frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('the preview frame carries the masked FP-pattern signal with the expected token, count, and per-value identity', () => {
    expect(preview.status).toBe(0);
    // The same rule surfaced three hits of three DISTINCT values (dedup does
    // not collapse them — different fingerprints): one genuine (the stub
    // judge's first-sorted survivor), two marked false positive — so the
    // emitted group's count is 2, not 1.
    expect(frame.counts).toEqual({ total: 3, important: 1, routine: 2 });

    expect(frame.falsePositivePatterns).toBeDefined();
    expect(frame.falsePositivePatterns).toHaveLength(1);
    const group = soleGroup(frame);

    const [firstKey] = REPEATED_FP_KEYS;
    if (firstKey === undefined) throw new Error('REPEATED_FP_KEYS must not be empty');
    // Every key in REPEATED_FP_KEYS masks identically (mask-collision), so any
    // one of them names the group's expected pattern.
    expect(group.pattern).toBe(safeMaskedMatch(firstKey));
    expect(group.count).toBe(2);
    expect(group.values).toHaveLength(2);
    for (const value of group.values) {
      expect(value.ruleId).toBe('secrets/aws-access-key');
      expect(typeof value.valueFingerprint).toBe('string');
      expect(value.valueFingerprint.length).toBeGreaterThan(0);
      expect(typeof value.keyVersion).toBe('number');
    }

    // No raw value from the seeded set ever crosses into the preview's
    // stdout — only the masked pattern token does.
    for (const raw of REPEATED_FP_KEYS) {
      expect(preview.stdout).not.toContain(raw);
    }
  });

  it("the checker's FP-signal grounding passes for the real emitted pattern/count and fails for an invented pattern or a fabricated count", () => {
    const group = soleGroup(frame);

    expect(checkFpSignalContract(frame, { pattern: group.pattern, count: group.count })).toEqual({
      ok: true,
    });

    const invented = checkFpSignalContract(frame, {
      pattern: 'not_a_real_pattern_never_emitted',
      count: group.count,
    });
    expect(invented.ok).toBe(false);
    expect(!invented.ok && invented.reason).toMatch(/invented pattern/);

    const fabricated = checkFpSignalContract(frame, {
      pattern: group.pattern,
      count: group.count + 41,
    });
    expect(fabricated.ok).toBe(false);
    expect(!fabricated.ok && fabricated.reason).toMatch(/fabricated count/);
  });
});

describe('FP-pattern signal fails open when no hit is marked a false positive', () => {
  let journey: SetupJourney;
  let preview: { stdout: string; stderr: string; status: number };
  let rawFrame: unknown;
  let frame: CalibrationFrame;

  beforeAll(() => {
    journey = new SetupJourney();
    // A clean scan: history is examined but surfaces nothing, so the model
    // verdict marks zero hits false positive.
    journey.seedCleanTranscript();

    journey.intro();
    journey.onboardHistorical('full');

    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage);
    rawFrame = readFrameJsonBlock(preview.stdout);
    frame = CalibrationFrame.parse(rawFrame);
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('the emitted frame OMITS falsePositivePatterns entirely — not an empty array — and is otherwise well-formed', () => {
    expect(preview.status).toBe(0);
    expect(frame.falsePositivePatterns).toBeUndefined();
    // The field is absent from the raw JSON, not present-and-empty.
    expect('falsePositivePatterns' in (rawFrame as Record<string, unknown>)).toBe(false);
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
    expect(frame.routineCategories).toEqual([]);
    expect(frame.surfacedCategories).toEqual([]);
  });

  it('a named pattern/count fails to ground against the missing signal', () => {
    const result = checkFpSignalContract(frame, { pattern: 'anything', count: 1 });
    expect(result.ok).toBe(false);
  });
});
