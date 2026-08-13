/**
 * The finding-narration contract, proven end-to-end against the REAL calibration
 * preview and remediation decision composition paths — not a standalone narrator
 * and not a hand-rolled frame.
 *
 * The calibration preview is the built `apply-suppressions.js` preview, driven
 * over a seeded transcript carrying one known, enumerated finding (a live-looking
 * AWS access key) through the real backfill -> apply-suppressions chain. The
 * remediation decision is the built `remediate.js` present mode
 * (`SetupJourney.remediationPresent`), fed the SAME captured frame text the
 * preview emitted on stdin — the same production wiring `commands/setup.md` uses
 * at the "Review leaked keys" entry. The remediation decision reads its own
 * `maskedFindings` from that fed text (`loadSecretLeakFindings`), so a narration
 * contract check run against the captured preview frame grounds both surfaces at
 * once: proven by cross-checking the remediation decision's own emitted
 * `secretCount` against that frame's `maskedFindings` length below.
 *
 * The checker (`checkNarrationContract`, `eval/prompt-contract.ts`) is the
 * automation owner; this file only drives the real composition paths and asserts
 * the checker's verdict over what they actually emitted.
 */
import {
  CalibrationFrame,
  type MaskedSecretFinding,
  severityFloorPosture,
} from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  carriesRunFindings,
  checkNarrationContract,
  type NarrationClaimSet,
} from '../../eval/prompt-contract.ts';
import { frameCalibration } from '../../src/calibration.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { SetupJourney, SURFACED_KEY } from './harness.ts';

function soleMaskedFinding(frame: CalibrationFrame): MaskedSecretFinding {
  const findings = frame.maskedFindings;
  if (findings?.length !== 1) {
    throw new Error('expected exactly one maskedFindings entry');
  }
  const [finding] = findings;
  if (finding === undefined) throw new Error('expected exactly one maskedFindings entry');
  return finding;
}

describe('finding narration grounds end-to-end over the real calibration preview and remediation decision composition paths', () => {
  let journey: SetupJourney;
  let preview: { stdout: string; status: number };
  let present: { stdout: string; status: number };
  let frame: CalibrationFrame;
  let finding: MaskedSecretFinding;
  let groundedClaims: NarrationClaimSet;

  beforeAll(() => {
    journey = new SetupJourney();
    // One live-looking AWS key surfaces as the run's single genuine finding; a
    // second, same-rule hit is dismissed as routine — a known, enumerated
    // finding (its meaning: an exposed AWS access key, grants API access if
    // leaked, should be rotated), matching this scenario's precondition.
    journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    journey.onboardModelJudge();

    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage);
    frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));
    finding = soleMaskedFinding(frame);

    // the remediation decision: the SAME captured frame text, on stdin, through the built present
    // mode — never a re-derived or hand-built frame.
    present = journey.remediationPresent(preview.stdout);

    groundedClaims = {
      spokenCounts: [
        { field: 'total', count: frame.counts.total },
        { field: 'important', count: frame.counts.important },
        { field: 'routine', count: frame.counts.routine },
      ],
      referencedValues: [finding.maskedToken],
      citedFindingFacts: [
        {
          maskedToken: finding.maskedToken,
          explanation: `An exposed ${finding.provider} access key (${finding.maskedToken}) turned up in a prior Claude Code session transcript at ${finding.where.filePath} — if it leaked, it grants API access to the account, so it should be rotated.`,
          assertedProvider: finding.provider,
          assertedLocation: finding.where.filePath,
          assertedState: finding.state,
        },
      ],
    };
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('both surfaces run cleanly and the remediation decision genuinely consumed the SAME captured frame — real composition, not a static or independently constructed one', () => {
    expect(preview.status).toBe(0);
    expect(present.status).toBe(0);
    expect(carriesRunFindings(frame)).toBe(true);
    expect(frame.maskedFindings).toHaveLength(1);

    // remediate.js's own emitted frame JSON is a distinct shape (a
    // BatchedRemediationDecision, not a CalibrationFrame — it carries no
    // per-finding facts of its own), so the cross-check that proves it read the
    // SAME maskedFindings is its secretCount matching the fed frame's count.
    const decisionFrame = readFrameJsonBlock(present.stdout) as { secretCount?: number };
    expect(decisionFrame.secretCount).toBe(frame.maskedFindings?.length);
  });

  it('the GROUNDED narration — labeled counts, a masked value, and a cited, explained finding — passes', () => {
    expect(checkNarrationContract(frame, groundedClaims)).toEqual({ ok: true });
  });

  it('an INVENTED count fails', () => {
    const invented: NarrationClaimSet = {
      ...groundedClaims,
      spokenCounts: [{ field: 'total', count: frame.counts.total + 41 }],
    };
    const result = checkNarrationContract(frame, invented);
    expect(result.ok).toBe(false);
  });

  it('an UNMASKED (raw) referenced value fails', () => {
    const raw: NarrationClaimSet = { ...groundedClaims, referencedValues: [SURFACED_KEY] };
    const result = checkNarrationContract(frame, raw);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/masked/);
  });

  it('an UNSUPPORTED claim — a cited finding with no corresponding frame fact — fails', () => {
    const unsupported: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [
        { maskedToken: 'AKIA****NOT_REAL', explanation: 'a finding that was never surfaced' },
      ],
    };
    const result = checkNarrationContract(frame, unsupported);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no corresponding frame fact/);
  });

  it('an invented attribute on the real token — wrong provider — fails as an unsupported claim', () => {
    const wrongProvider: NarrationClaimSet = {
      ...groundedClaims,
      citedFindingFacts: [
        {
          maskedToken: finding.maskedToken,
          explanation: 'A stray key, unrelated to AWS.',
          assertedProvider: 'stripe',
        },
      ],
    };
    const result = checkNarrationContract(frame, wrongProvider);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/invented finding attribute/);
  });

  it('a bare count-recital that does not explain the known finding FAILS — required at both the calibration preview and the remediation decision', () => {
    const bare: NarrationClaimSet = {
      spokenCounts: groundedClaims.spokenCounts,
      referencedValues: [],
      citedFindingFacts: [],
    };
    const result = checkNarrationContract(frame, bare);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/bare count recital/);
  });

  it('an independently constructed frame fails to ground the real narration — the checked frame must be the run’s own', () => {
    // Built by frameCalibration() directly in this test, never by the real
    // script chain — a different masked finding for the "same" story. Grounded
    // claims that cite the REAL captured finding's token/location must not
    // validate against this other, merely well-shaped frame.
    const independentFrame = frameCalibration(
      {
        categories: [{ category: 'secret', genuineCount: 1, fpCount: 0, egress: false }],
        posture: severityFloorPosture(),
      },
      [
        {
          provider: finding.provider,
          maskedToken: 'AKIA****INDEPENDENT',
          where: { filePath: 'independently/constructed.ts' },
          state: finding.state,
        },
      ],
    ).frame;

    const result = checkNarrationContract(independentFrame, groundedClaims);
    expect(result.ok).toBe(false);
  });
});

describe('fail-open leg: the narration signal is absent — both the calibration preview and the remediation decision degrade to the unmodified static frame', () => {
  let journey: SetupJourney;
  let preview: { stdout: string; status: number };
  let present: { stdout: string; status: number };
  let frame: CalibrationFrame;

  beforeAll(() => {
    journey = new SetupJourney();
    // A scan that runs but surfaces nothing — no maskedFindings signal for
    // either surface to narrate over.
    journey.seedCleanTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    journey.onboardModelJudge();

    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage);
    frame = CalibrationFrame.parse(readFrameJsonBlock(preview.stdout));

    present = journey.remediationPresent(preview.stdout);
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('the calibration preview degrades to the unmodified static frame — no maskedFindings signal, all counts zero', () => {
    expect(preview.status).toBe(0);
    expect(carriesRunFindings(frame)).toBe(false);
    expect(frame.counts).toEqual({ total: 0, important: 0, routine: 0 });
  });

  it('the remediation decision degrades honestly too — no decision, and no frame JSON is emitted for it (nothing to narrate)', () => {
    expect(present.status).toBe(0);
    expect(present.stdout).toContain("No exposed keys to deal with — you're clear.");
    expect(readFrameJsonBlock(present.stdout)).toBeUndefined();
  });

  it('no narration is invented over the missing-signal frame — any attempted finding claim fails the checker', () => {
    const inventedNarration: NarrationClaimSet = {
      spokenCounts: [{ field: 'total', count: 0 }],
      referencedValues: [],
      citedFindingFacts: [
        { maskedToken: 'AKIA****INVENTED', explanation: 'a finding that was never surfaced' },
      ],
    };
    const result = checkNarrationContract(frame, inventedNarration);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no corresponding frame fact/);
  });
});
