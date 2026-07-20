/**
 * The secret-leak remediation chain, proven runnable end-to-end by DIRECT
 * invocation: a findings set + a RemediationEntryContext and NO wizard state.
 * This is the entry-point-agnostic contract the pre-push and /aka:secretscan
 * entries reuse.
 *
 * The chain is driven against a throwaway ~/.aka home seeded (NOT via the
 * wizard) with a secret-leak findings set: real transcript artifacts carrying
 * raw leaked keys plus a persisted calibration frame (the backfill's output) whose
 * masked per-finding summaries the loader reads. The batched remediation
 * decision (step 1) is presented directly against the real DI core (the
 * findings loader, the batched-decision core, the decision layout formatter)
 * over the real local store; no module is mocked.
 *
 * The redact -> standing-posture -> resolved-deliverable spine
 * downstream of that decision (steps 2-4) is driven in ONE call through the
 * BUILT `scripts/remediate.js` — not a hand-assembled module composition — fed
 * the SAME persisted calibration frame text the findings loader reads, and
 * spawned with its cwd pointed at an isolated temporary git repository the
 * harness creates and cleans up (never the ai-tc working tree, since the
 * deliverable resolver resolves the repo root from the script's own cwd). This
 * proves the chain's full spine to closure — remediation decision -> redaction
 * -> standing posture -> the resolved deliverable (rotation-checklist.md
 * written at a real repo root plus the resolved summary) — from the production
 * entry, asserting the rotation-checklist entries and the resolved summary
 * compose from the same checklist-entry model.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type {
  BatchedRemediation,
  CalibrationFrame,
  MaskedSecretFinding,
  RotationChecklistEntry,
} from '@akasecurity/schema';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { selectSecretScanContinuation } from '../../src/command-registry.ts';
import {
  buildChecklistEntries,
  renderChecklistMarkdown,
} from '../../src/remediation/rotation-checklist.ts';
import {
  REMEDIATION_LEAK_RAW_KEYS,
  type RemediationDrive,
  SetupJourney,
  type StepResult,
} from './harness.ts';

// The chaining line names one 'N more worth a look' figure; the count itself is
// the caller's, so the harness just threads a fixed one and asserts the command.
const MORE_COUNT = 1;

describe('direct-invocation remediation chain, no wizard state', () => {
  let journey: SetupJourney;
  let drive: RemediationDrive;
  // The isolated temp git repository the built script is spawned with as its
  // cwd — the deliverable resolver's write target — never the ai-tc working tree.
  let repoRoot: string;

  // Captured once across the whole spine run.
  let findings: MaskedSecretFinding[];
  let frame: CalibrationFrame;
  let decision: BatchedRemediation;
  let layout: string;
  let entries: RotationChecklistEntry[];
  let postureBaseline: string | undefined;
  let routeResult: StepResult;
  let transcriptsAfter: string[];
  let postureAfter: string | undefined;
  let checklistContents: string;

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
    // The SAME checklist-entry model the built script's deliverable resolver
    // composes from these findings, computed independently here so the
    // written file and the resolved summary can each be checked against it.
    entries = buildChecklistEntries(findings);

    repoRoot = mkdtempSync(join(tmpdir(), 'aka-remediation-journey-repo-'));
    mkdirSync(join(repoRoot, '.git'));

    // The store's floor-seeded default, read BEFORE the built-script run so the
    // Redact selection below is an observable change, not a coincidental match.
    postureBaseline = drive.postureFromStore();

    // Steps 2->3->4 in ONE built-script invocation: `remediate.js --option
    // redact-rotation-checklist --posture redact`, fed the SAME calibration
    // frame text the findings loader above read, driving the redact -> standing
    // posture persistence -> resolved deliverable spine from the production
    // entry rather than a hand-assembled module composition.
    routeResult = journey.remediationRoute(
      drive.persistedFrame,
      'redact-rotation-checklist',
      'redact',
      repoRoot,
    );
    transcriptsAfter = drive.transcriptContents();
    // The 'secret' posture read back on a FRESH connection, so persistence is
    // durable rather than a same-connection artifact.
    postureAfter = drive.postureFromStore();
    checklistContents = readFileSync(join(repoRoot, 'rotation-checklist.md'), 'utf8');
  }, 120_000);

  afterAll(() => {
    rmSync(repoRoot, { recursive: true, force: true });
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

  it('step 2: "Redact + rotation checklist" redacts the real transcript artifacts through the built remediate.js', () => {
    expect(routeResult.status).toBe(0);
    expect(routeResult.stdout).toContain('✓ Redacted 3 keys across 2 transcripts');
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

  it('step 3: the built remediate.js persists secret→Redact to the policies store', () => {
    // The store's seeded default is 'warn', so the standing Redact choice is an
    // observable change — not a coincidental match with the baseline.
    expect(postureBaseline).toBe('warn');
    expect(routeResult.stdout).toContain("✓ Set 'secret' posture to redact");
    // The 'secret' posture is durable in the policies store — read back on a fresh
    // connection, so future secret detections are governed by it.
    expect(postureAfter).toBe('redact');
  });

  it('step 4: rotation-checklist.md is written at the repo root, most-exposed-first, masked, with per-provider console paths', () => {
    expect(existsSync(join(repoRoot, 'rotation-checklist.md'))).toBe(true);
    expect(routeResult.stdout).toContain('✓ Drafted rotation-checklist.md (repo root)');

    // Three DISTINCT provider+masked-token entries — the fixture's three keys
    // never collapse into one row. Every seeded entry has the same occurrence
    // spread (1), so exposure age (oldest first) is the real order discriminator
    // here, per the spread-then-age-then-provider/token ordering rule.
    expect(entries.map((e) => e.provider)).toEqual(['github', 'stripe', 'aws']);
    for (const entry of entries) {
      expect(checklistContents).toContain(
        `- [ ] ${entry.provider} — ${entry.maskedToken} — ${entry.consolePath}`,
      );
    }
    // Each recognized-provider entry carries its own per-provider console path.
    expect(checklistContents).toContain('dashboard.stripe.com');
    expect(checklistContents).toContain('console.aws.amazon.com');
    expect(checklistContents).toContain('github.com');

    // No raw leaked key ever appears in the written checklist.
    for (const raw of REMEDIATION_LEAK_RAW_KEYS) {
      expect(checklistContents).not.toContain(raw);
    }
  });

  it('step 4: the resolved summary reports real, independently derived redacted-key and transcript counts', () => {
    expect(routeResult.stdout).toContain('Leaked secrets — resolved');

    // M (transcripts) is derived from the DISTINCT where.filePath values the
    // seeded findings carry — not the key count (N=3) relabelled. The fixture
    // spreads 3 keys across exactly 2 transcript artifacts (M != N), so this is a
    // real, independent count.
    const distinctTranscripts = new Set(findings.map((f) => f.where.filePath));
    expect(distinctTranscripts.size).toBe(2);
    expect(distinctTranscripts.size).not.toBe(findings.length);

    expect(routeResult.stdout).toContain(
      `✓ Redacted 3 keys across ${String(distinctTranscripts.size)} transcripts`,
    );
    expect(routeResult.stdout).toContain('✓ Drafted rotation-checklist.md (repo root)');
  });

  it('step 4: the inline checklist preview matches the written rotation-checklist.md entry-for-entry', () => {
    // Both the file and the built script's stdout preview render from the SAME
    // ordered RotationChecklistEntry[] through renderChecklistMarkdown.
    expect(checklistContents).toBe(renderChecklistMarkdown(entries));

    const previewLines = routeResult.stdout.split('\n').filter((line) => line.startsWith('- [ ] '));
    expect(previewLines).toEqual(checklistContents.trimEnd().split('\n'));

    for (const raw of REMEDIATION_LEAK_RAW_KEYS) {
      // The raw keys never surface anywhere the harness rendered — the layout,
      // the written checklist, or the built script's own stdout.
      expect(layout).not.toContain(raw);
      expect(routeResult.stdout).not.toContain(raw);
    }
  });
});
