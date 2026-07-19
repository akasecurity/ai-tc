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
 *
 * The direct Redact+checklist path (remediation.journey.test.ts) is not
 * re-proven here, per its declared scope.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import {
  BatchedRemediationDecision,
  CalibrationFrame,
  SetupHandoffOffer,
} from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { selectSecretScanContinuation } from '../../src/command-registry.ts';
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

  it("'Redact only' through the built script redacts the real transcript artifact and reports the real count, writing no posture and no deliverable", () => {
    // Runs AFTER 'Leave' (which does not mutate), so the raw key is still on disk.
    expect(readFileSync(transcriptPath, 'utf8')).toContain(SURFACED_KEY);
    const postureBefore = readPosture(journey.storeDir);

    const redactOut = journey.remediationRoute(preview, 'redact-only').stdout;

    expect(redactOut).toContain(renderRedactionConfirmation(1));
    const after = readFileSync(transcriptPath, 'utf8');
    expect(after).not.toContain(SURFACED_KEY);
    expect(after).toContain('[REDACTED:SECRET]');
    // 'Redact only' redacts and nothing more — no posture write, no deliverable.
    expect(readPosture(journey.storeDir)).toBe(postureBefore);
    expect(existsSync(STRAY_ROTATION_CHECKLIST)).toBe(false);
  });

  it('an unreadable calibration frame degrades to an honest read-failure note — never a false all-clear or a false "redacted 0 keys" success', () => {
    // The wizard mis-pipes a block that is not the calibration frame: the loader
    // returns undefined (a read/parse fault, distinct from a clean empty read),
    // so neither mode may claim an all-clear or a success off a frame it never read.
    const brokenFrame = 'this is not a calibration frame block';

    const presentOutBroken = journey.remediationPresent(brokenFrame).stdout;
    expect(presentOutBroken).toContain('Could not read the calibration frame');
    expect(presentOutBroken).not.toContain('No secret-leak findings to review');

    const redactOutBroken = journey.remediationRoute(brokenFrame, 'redact-only').stdout;
    expect(redactOutBroken).toContain('Could not read the calibration frame');
    expect(redactOutBroken).not.toContain(renderRedactionConfirmation(0));
    expect(redactOutBroken.toLowerCase()).not.toContain('redacted');
  });
});
