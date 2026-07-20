/**
 * The secret-leak remediation chain driven at its PRODUCTION entry — the
 * built `scripts/remediate.js` `commands/setup.md` runs when the
 * user chooses "Review leaked keys" at frame 0.6 — rather than by a
 * hand-assembled module composition.
 *
 * ONE real spine drives everything: `intro.js` -> `onboard.js` -> `backfill.js`
 * -> `apply-suppressions.js` preview/confirm -> `firstrun.js`, exactly as
 * yes-scan.journey.test.ts does, over a seeded transcript that leaks a real
 * live key. That preview's stdout IS the "persisted calibration frame"
 * `loadSecretLeakFindings` reads, and the seeded transcript is a real on-disk
 * artifact that still holds the raw key (the backfill records it but never
 * strikes it). The wizard threads that SAME captured frame text into
 * `remediate.js` on stdin — for the remediation-decision presentation AND for every option
 * route — so this harness does too. Because the frame carries the REAL
 * transcript path (not a placeholder), the hardened production adapter
 * `redactSurfacedSecrets` can locate and strike the key exactly as it will for
 * a real user — proving production reachability rather than masking it behind a
 * synthetic fixture.
 *
 * Proves:
 *  - the entry into the remediation decision firing from a real frame-0.6 decision,
 *    agreeing on N.
 *  - the real-count leg: the four-option remediation-decision
 *    presentation, masked-only finding table over the real finding, no 'case'
 *    vocabulary, count templated over the real findings.
 *  - 'Leave' exits cleanly: no redaction, no posture, no
 *    deliverable, key still readable on disk.
 *  - 'Redact only' — the built script strikes the real key in the real
 *    transcript artifact and reports the real count, writing no posture and no
 *    deliverable.
 *  - 'Redact only' -> the standing-posture step, parameterized over all four
 *    palette choices (Redact/Warn/Block/Monitor): the built script forwards
 *    the user's actual selection through to the policies store rather than
 *    hardcoding Redact or mishandling the other three.
 *
 * The direct Redact+checklist path (remediation.journey.test.ts) is not
 * re-proven here, per its declared scope.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import {
  BatchedRemediationDecision,
  type BuiltinPolicyId,
  builtinPolicyToAction,
  CalibrationFrame,
  SetupHandoffOffer,
} from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { selectSecretScanContinuation } from '../../src/command-registry.ts';
import { presentStandingSecretPosture } from '../../src/remediation/posture.ts';
import { renderRedactionConfirmation } from '../../src/remediation/render.ts';
import { readFrameJsonBlock } from '../../src/setup-frame-json.ts';
import { planPathFromPreview, PLUGIN_ROOT, SetupJourney, SURFACED_KEY } from './harness.ts';

// No route ever writes a rotation-checklist.md relative to the invocation's
// working directory (only the built script's own cwd) unless the
// 'redact-rotation-checklist' path resolved the deliverable — not exercised
// here. The built script inherits this test process's cwd (PLUGIN_ROOT).
const STRAY_ROTATION_CHECKLIST = join(PLUGIN_ROOT, 'rotation-checklist.md');

// The 'secret' posture read straight from the store the production entry
// wrote to, on a fresh connection — so a same-connection artifact never masks
// a missed (or unwanted) write.
function readPosture(storeDir: string): string | undefined {
  const db = openLocalDatabase(storeDir);
  try {
    return db.policies.getCategoryAction('secret');
  } finally {
    db.close();
  }
}

describe('frame 0.6 -> remediation decision -> option routing: production entry driven from a real calibration frame', () => {
  let journey: SetupJourney;
  let transcriptPath: string;
  let preview: string;
  let calibrationFrame: CalibrationFrame;
  let firstRun: string;
  let presentOut: string;
  let decision: BatchedRemediationDecision;

  beforeAll(() => {
    journey = new SetupJourney();
    transcriptPath = journey.seedTranscript();

    journey.intro();
    journey.onboardHistorical('full');
    const triage = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triage).stdout;
    calibrationFrame = CalibrationFrame.parse(readFrameJsonBlock(preview));
    journey.applyConfirm(planPathFromPreview(preview));

    // Frame 0.6: the built firstrun.js, fed the real surfaced counts this
    // calibration frame carries — the same frame the production remediation
    // entry below reads.
    firstRun = journey.firstRun(
      calibrationFrame.counts.important,
      calibrationFrame.maskedFindings?.length ?? 0,
    ).stdout;

    // The user chooses "Review leaked keys" at frame 0.6: the wizard runs the
    // built remediate.js, piping in the SAME calibration frame text frame 0.6
    // itself was derived from.
    presentOut = journey.remediationPresent(preview).stdout;
    decision = BatchedRemediationDecision.parse(readFrameJsonBlock(presentOut));
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('frame 0.6 offers the chain entry exactly when live keys surfaced, and the SAME persisted frame drives remediate.js to a real remediation decision agreeing on N', () => {
    expect(calibrationFrame.maskedFindings).toHaveLength(1);
    const offer = SetupHandoffOffer.parse(readFrameJsonBlock(firstRun));
    expect(offer.liveKeys).toBe(1);
    expect(offer.options.map((o) => o.id)).toEqual([
      'enter-remediation',
      'open-dashboard',
      'not-now',
    ]);

    // The production entry, driven from the SAME frame text, produces a real
    // decision whose count agrees with frame 0.6's live-key count — two
    // separately-spawned built scripts reading the one persisted frame.
    expect(decision.kind).toBe('decision');
    expect(decision.secretCount).toBe(offer.liveKeys);
  });

  it('the real-count leg: the remediation-decision presentation is the full four-option layout over the real finding, masked-only, no "case" vocabulary', () => {
    // The count is templated from the real surfaced finding (1), never hardcoded.
    expect(decision.secretCount).toBe(1);
    expect(decision.prompt).toBe('1 exposed secret key found in old transcripts');
    expect(decision.options.map((o) => o.id)).toEqual([
      'redact-rotation-checklist',
      'redact-only',
      'set-secret-redact',
      'leave',
    ]);
    expect(decision.options.map((o) => o.label)).toEqual([
      'Redact + rotation checklist',
      'Redact only',
      "Set 'secret' to redact",
      'Leave',
    ]);

    // The full remediation-decision layout: the masked finding table, the recommendation
    // line, and the registry-driven chaining line — reached from the built
    // script's own stdout, not a re-composed module.
    expect(presentOut).toContain('PROVIDER');
    expect(presentOut).toContain('TOKEN');
    expect(presentOut).toContain('STATE');
    expect(presentOut).toContain('unknown');
    expect(presentOut).not.toContain('still valid');
    expect(presentOut).toContain("I'd redact them and get you rotating, most-exposed first");
    expect(presentOut).toContain(`run ${selectSecretScanContinuation()}`);

    // The Where column carries the REAL transcript path the pipeline recorded —
    // not a '(location unavailable)' placeholder — so the finding the user sees
    // is the same on-disk artifact the redact path below actually strikes.
    expect(calibrationFrame.maskedFindings?.[0]?.where.filePath).toBe(transcriptPath);
    expect(presentOut).not.toContain('(location unavailable)');

    // No raw leaked key crosses into the production entry's output — masked only.
    expect(presentOut).not.toContain(SURFACED_KEY);

    // No "case" vocabulary anywhere the production entry prints.
    expect(presentOut.toLowerCase()).not.toContain('case');
  });

  it("choosing 'Leave' through the built script exits cleanly — no redaction, no posture, no deliverable", () => {
    const before = readFileSync(transcriptPath, 'utf8');
    const postureBefore = readPosture(journey.storeDir);

    const leaveOut = journey.remediationRoute(preview, 'leave').stdout;

    // The built script actually reports the clean exit — not a silently empty
    // stdout that would vacuously satisfy the observables below.
    expect(leaveOut.trim().length).toBeGreaterThan(0);
    expect(leaveOut.toLowerCase()).not.toContain('case');
    // The transcript artifact is untouched — the raw key is still readable.
    expect(readFileSync(transcriptPath, 'utf8')).toBe(before);
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    // No posture change and no rotation-checklist.md deliverable.
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
    expect(existsSync(STRAY_ROTATION_CHECKLIST)).toBe(false);
  });

  it("'Redact only' through the built script fails loud on a missing --posture — no redaction, no posture write", () => {
    // Runs AFTER 'Leave' (which does not mutate), so the raw key is still on disk.
    const before = readFileSync(transcriptPath, 'utf8');
    const postureBefore = readPosture(journey.storeDir);

    const result = journey.remediationRoute(preview, 'redact-only');

    expect(result.status).not.toBe(0);
    expect(readFileSync(transcriptPath, 'utf8')).toBe(before);
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
  });

  it('an unreadable calibration frame degrades to an honest read-failure note — never a false all-clear or a false "redacted 0 keys" success', () => {
    // The wizard mis-pipes a block that is not the calibration frame: the loader
    // returns undefined (a read/parse fault, distinct from a clean empty read),
    // so neither mode may claim an all-clear or a success off a frame it never read.
    const brokenFrame = 'this is not a calibration frame block';

    const presentOutBroken = journey.remediationPresent(brokenFrame).stdout;
    expect(presentOutBroken).toContain('Could not read the calibration frame');
    expect(presentOutBroken).not.toContain('No secret-leak findings to review');

    // A valid --posture, so the route clears posture validation (which precedes
    // the frame read) and the unreadable frame itself is what degrades honestly.
    const redactOutBroken = journey.remediationRoute(brokenFrame, 'redact-only', 'redact').stdout;
    expect(redactOutBroken).toContain('Could not read the calibration frame');
    expect(redactOutBroken).not.toContain(renderRedactionConfirmation(0));
    expect(redactOutBroken.toLowerCase()).not.toContain('redacted');
  });
});

// The 'Redact only' -> standing-posture leg re-proven from the BUILT
// remediate.js and PARAMETERIZED over all four palette choices — replacing an
// earlier leg that rested on an app-level composition
// (batched-decision.scenario.test.ts). A separate top-level describe (not the
// outer beforeAll's shared journey): 'redact-only' physically strikes the
// key, so proving all four choices at N=1 each needs its own fresh transcript
// + calibration frame per choice, not one shared spine reused across four
// mutating runs.
describe("'Redact only' presents the standing-posture step, parameterized over all four choices, driven from the built remediate.js", () => {
  it('the standing-posture prompt offers exactly Redact / Warn / Block / Monitor, in that order', () => {
    const step = presentStandingSecretPosture();
    expect(step.prompt).toContain("Set the 'secret' posture");
    expect(step.options.map((o) => o.level)).toEqual(['redact', 'warn', 'block', 'monitor']);
    expect(step.options.map((o) => o.label)).toEqual(['Redact', 'Warn', 'Block', 'Monitor']);
  });

  it.each<BuiltinPolicyId>(['redact', 'warn', 'block', 'monitor'])(
    "'Redact only' through the built script honors the user's standing-posture selection (%s): strikes the real key and persists the corresponding posture",
    (level) => {
      const run = new SetupJourney();
      try {
        const transcript = run.seedTranscript();
        run.intro();
        run.onboardHistorical('full');
        const triage = run.backfillTriage().stdout;
        const runPreview = run.applyPreview(triage).stdout;
        CalibrationFrame.parse(readFrameJsonBlock(runPreview));
        run.applyConfirm(planPathFromPreview(runPreview));

        // The confirm write's recommended posture seeds 'secret'->warn — the
        // same baseline every fresh run starts from. Overwrite it (the real
        // onboard.ts writer, not a store-internal poke) to a level that
        // genuinely differs from the level under test, so a passing readback
        // below can only mean THIS run's write landed — never a pre-existing
        // value that happens to already match (a real risk for the Warn case,
        // since Warn IS the seeded baseline).
        const distinctSeed: BuiltinPolicyId = level === 'monitor' ? 'block' : 'monitor';
        run.onboardPosture({ secret: distinctSeed });
        // getCategoryAction reads back the stored ActionTaken, not the palette
        // id — monitor maps to 'log' (builtinPolicyToAction), the rest are
        // identity-mapped.
        expect(readPosture(run.storeDir)).toBe(builtinPolicyToAction(distinctSeed));

        const redactOut = run.remediationRoute(runPreview, 'redact-only', level).stdout;

        // A real frame-0.4 preview seeds a single leaked key, so the
        // redaction count stays at N=1 across every choice — the sweep is
        // over the four posture choices, not the finding count.
        expect(redactOut).toContain(renderRedactionConfirmation(1));
        expect(redactOut).toContain(`✓ Set 'secret' posture to ${level}`);
        const after = readFileSync(transcript, 'utf8');
        expect(after).not.toContain(SURFACED_KEY);
        expect(after).toContain('[REDACTED:SECRET]');

        // Persisted durably — read on a FRESH connection — to the level the
        // user actually chose, not hardcoded to Redact. 'Redact only' still
        // generates no deliverable.
        expect(readPosture(run.storeDir)).toBe(builtinPolicyToAction(level));
        expect(existsSync(STRAY_ROTATION_CHECKLIST)).toBe(false);
      } finally {
        run.cleanup();
      }
    },
    30_000,
  );
});
