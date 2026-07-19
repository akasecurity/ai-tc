/**
 * The secret-leak remediation chain, proven runnable by DIRECT invocation: a
 * findings set + a RemediationEntryContext and NO wizard state. This is the
 * entry-point-agnostic contract the pre-push and /aka:secretscan entries reuse.
 *
 * The chain is driven end-to-end against a throwaway ~/.aka home seeded (NOT via
 * the wizard) with a secret-leak findings set: real transcript artifacts carrying
 * raw leaked keys plus a persisted calibration frame (the backfill's output) whose
 * masked per-finding summaries the loader reads. The drive wires the real DI core —
 * the findings loader, the batched-decision core, the decision layout formatter, the
 * option router bound to the real redaction mechanism, and the standing-posture writer —
 * over the real local store; no module is mocked.
 *
 * This drives the chain's advanced spine (remediation decision → redaction → standing
 * posture); it does not assert the resolved deliverable. The resolved summary
 * and the rotation-checklist.md deliverable do not exist yet, so this harness
 * deliberately asserts only that spine, not the resolved deliverable.
 */
import type {
  BatchedRemediation,
  CalibrationFrame,
  MaskedSecretFinding,
} from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { selectSecretScanContinuation } from '../../src/command-registry.ts';
import type { RemediationRouteOutcome } from '../../src/remediation/chain.ts';
import type {
  StandingPostureResult,
  StandingSecretPostureStep,
} from '../../src/remediation/posture.ts';
import { REMEDIATION_LEAK_RAW_KEYS, type RemediationDrive, SetupJourney } from './harness.ts';

// The chaining line names one 'N more worth a look' figure; the count itself is
// the caller's, so the harness just threads a fixed one and asserts the command.
const MORE_COUNT = 1;

describe('direct-invocation remediation chain, no wizard state', () => {
  let journey: SetupJourney;
  let drive: RemediationDrive;

  // Captured once across the whole advanced spine run.
  let findings: MaskedSecretFinding[];
  let frame: CalibrationFrame;
  let decision: BatchedRemediation;
  let layout: string;
  let redactOutcome: RemediationRouteOutcome;
  let transcriptsAfter: string[];
  let c3: StandingSecretPostureStep;
  let postureBaseline: string | undefined;
  let postureResult: StandingPostureResult;
  let postureAfter: string | undefined;

  beforeAll(() => {
    journey = new SetupJourney();
    drive = journey.remediation();

    // Seed the findings set NOT via the wizard: real transcript artifacts holding
    // raw leaked keys under the throwaway home, plus a persisted calibration frame
    // (the backfill's output) that ALSO records a pii finding so the secret-only
    // exclusion below is a real filter, not a vacuous empty set.
    drive.seedSecretLeaks();

    // The findings are READ from the seeded backfill frame (never synthesized),
    // and the chain is invoked directly with an entry context and
    // no wizard state.
    findings = drive.loadFindings() ?? [];
    frame = drive.frame;
    decision = drive.present({ entrySource: 'first-run' });
    layout = drive.renderLayout(findings, MORE_COUNT);

    // Step 2 — the user selects 'Redact + rotation checklist': the leaked keys are
    // redacted in the transcript artifacts. The deliverable half does not exist yet,
    // so the route records that a checklist was requested but writes none here.
    redactOutcome = drive.route('redact-rotation-checklist');
    transcriptsAfter = drive.transcriptContents();

    // Step 3 — the standing-posture prompt appears; the user selects Redact and
    // it persists to the policies store via applyCategoryPosture. The baseline
    // is read first (the store's seeded 'warn' default) so the write is an
    // observable change, and the after-value is read on a FRESH connection so
    // persistence is durable, not a same-connection artifact.
    c3 = drive.presentPosture();
    postureBaseline = drive.postureFromStore();
    postureResult = drive.writePosture('redact');
    postureAfter = drive.postureFromStore();
  }, 120_000);

  afterAll(() => {
    journey.cleanup();
  });

  it('reads the secret-leak findings from the seeded backfill frame — three, secret-only, PII excluded', () => {
    // The frame genuinely records pii activity, so "only the secret findings enter"
    // is a real filter over a mixed source, not an empty set.
    expect(frame.findingKinds.map((k) => k.category)).toContain('pii');
    // The loader surfaced exactly the three seeded secret summaries — read from the
    // frame, matching the seeded findings, never hardcoded.
    expect(findings).toHaveLength(3);
    expect(findings).toEqual(drive.leaks.map((l) => l.finding));
    // Every loaded finding is a masked secret summary pointing at a seeded artifact.
    for (const f of findings) {
      expect(drive.leaks.some((l) => l.filePath === f.where.filePath)).toBe(true);
      expect(f.maskedToken).not.toBe('');
    }
  });

  it('presents the batched remediation decision directly — real templated count, exactly four options', () => {
    expect(decision.kind).toBe('decision');
    if (decision.kind !== 'decision') return;
    // The chain was entered directly with the supplied entry context, no wizard.
    expect(decision.entrySource).toBe('first-run');
    // One decision moment over the whole set; the count templates over the real
    // three findings with no unverifiable 'still valid' claim.
    expect(decision.secretCount).toBe(3);
    expect(decision.prompt).toContain('3 exposed secret keys found in old transcripts');
    expect(decision.prompt.toLowerCase()).not.toContain('still valid');
    // Exactly the four options, in stable order — no more, no fewer.
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
  });

  it('decision layout: a masked-only finding table over the secret findings — no raw key crosses', () => {
    // The provider/token/where/state table renders each finding's masked token and
    // its honest 'unknown' state, one row per seeded artifact.
    expect(layout).toContain('PROVIDER');
    expect(layout).toContain('TOKEN');
    expect(layout).toContain('STATE');
    expect(layout).toContain('unknown');
    expect(layout).not.toContain('still valid');
    for (const leak of drive.leaks) {
      expect(layout).toContain(leak.finding.maskedToken);
      expect(layout).toContain(leak.filePath);
      // The RAW leaked key never appears in the rendered layout — the masked token
      // is distinct from the raw value, so this is a real raw-free assertion.
      expect(leak.finding.maskedToken).not.toBe(leak.rawValue);
      expect(layout).not.toContain(leak.rawValue);
    }
    // The recommendation line and the chaining line name the registered secret-scan
    // continuation, resolved against the real installed command registry.
    expect(layout).toContain("I'd redact them and get you rotating, most-exposed first");
    expect(layout).toContain(`run ${selectSecretScanContinuation()}`);
  });

  it('step 2: "Redact + rotation checklist" redacts the real transcript artifacts', () => {
    expect(redactOutcome).toEqual({
      kind: 'redacted',
      withRotationChecklist: true,
      redactedKeys: 3,
    });
    // The three leaked keys are no longer readable in the transcript artifacts —
    // each was struck in place and replaced with the redaction placeholder.
    expect(transcriptsAfter).toHaveLength(3);
    for (const [i, contents] of transcriptsAfter.entries()) {
      const leak = drive.leaks[i];
      expect(leak).toBeDefined();
      if (leak === undefined) continue;
      expect(contents).not.toContain(leak.rawValue);
      expect(contents).toContain('[REDACTED:SECRET]');
    }
  });

  it('step 3: the standing-posture prompt appears and persists secret→Redact to the policies store', () => {
    // The standing-posture palette offers exactly Redact / Warn / Block / Monitor.
    expect(c3.prompt).toContain("Set the 'secret' posture");
    expect(c3.options.map((o) => o.level)).toEqual(['redact', 'warn', 'block', 'monitor']);
    expect(c3.options.map((o) => o.label)).toEqual(['Redact', 'Warn', 'Block', 'Monitor']);

    // The store's seeded default is 'warn', so the standing Redact choice is an
    // observable change — not a coincidental match with the baseline.
    expect(postureBaseline).toBe('warn');
    expect(postureResult).toEqual({ persisted: true, level: 'redact' });
    // The 'secret' posture is durable in the policies store — read back on a fresh
    // connection, so future secret detections are governed by it.
    expect(postureAfter).toBe('redact');
  });

  it('advanced, not closed: no rotation-checklist.md and no resolved summary are claimed here', () => {
    // The deliverable half does not exist yet. The route
    // records the checklist REQUEST but produces no deliverable, and this harness
    // asserts no resolved-summary copy — the journey runs advanced, not closed.
    if (redactOutcome.kind !== 'redacted') throw new Error('expected a redacted outcome');
    expect(redactOutcome.withRotationChecklist).toBe(true);
    expect(drive.rotationChecklistExists()).toBe(false);
    for (const raw of REMEDIATION_LEAK_RAW_KEYS) {
      // The raw keys never surface anywhere the harness rendered.
      expect(layout).not.toContain(raw);
    }
  });
});
