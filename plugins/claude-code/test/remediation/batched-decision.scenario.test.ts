import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import type {
  CalibrationPreview,
  MaskedSecretFinding,
  RemediationEntryContext,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { frameCalibration } from '../../src/calibration.ts';
import {
  readRegisteredCommands,
  selectSecretScanContinuation,
} from '../../src/command-registry.ts';
import { presentBatchedRemediation, routeRemediationOption } from '../../src/remediation/chain.ts';
import { loadSecretLeakFindings } from '../../src/remediation/findings.ts';
import {
  presentStandingSecretPosture,
  writeStandingSecretPosture,
} from '../../src/remediation/posture.ts';
import {
  type RedactionScope,
  type RedactionTarget,
  redactLeakedKeys,
} from '../../src/remediation/redact.ts';
import { renderRemediationDecision } from '../../src/remediation/render.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';

// The batched four-option remediation decision, driven at the APP-LEVEL seam: the real
// chain wired end to end with no new orchestrator. A persisted calibration frame
// (the backfill precondition) → the real findings loader → the real
// batched-decision core → the real decision layout formatter → the real option router
// bound to the real redaction mechanism and the real standing-posture writer over a
// REAL local store. Every observable the scenario names is asserted against real
// behavior, not a mock.

// Canonical AWS access-key ids composed at runtime so the repo's own secret scan
// does not flag this file (mirrors redact.test.ts and redact-only.scenario.test.ts).
// These are the RAW leaked values that live in the transcript artifacts; the
// finding table must surface only the masked previews below, never these.
const RAW_KEYS = [
  ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
  ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join(''),
  ['AKIA', '2E7HTNXKP4LMKD9V'].join(''),
];

// The masked preview each finding carries into the frame — a masked form of the
// raw key, distinct from it so the raw-free assertions are real, not tautologies.
const MASKED_TOKEN = 'AKIA****************';

// The calibration preview the backfill recorded: 3 surfaced secret findings AND a
// customer-data / PII finding. The pii genuine hit makes
// the secret-only exclusion OBSERVABLE — the source frame genuinely carries pii
// activity in its findingKinds, so "only the 3 secret findings enter the flow" is a
// real filter, never a vacuous empty set.
const preview: CalibrationPreview = {
  categories: [
    { category: 'secret', genuineCount: 3, fpCount: 0, egress: false },
    { category: 'pii', genuineCount: 1, fpCount: 20, egress: false },
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

const FIRST_RUN: RemediationEntryContext = { entrySource: 'first-run' };

describe('batched four-option remediation decision (app-level: no case, secret-only, full layout, standing posture)', () => {
  // The transcript artifact root the leaked keys live under (redaction is scoped to
  // it), the real local store base (settings/ + data/aka.db), and a working dir
  // where a rotation-checklist.md would land if a non-deliverable path wrongly wrote one.
  let transcriptRoot: string;
  let base: string;
  let workingDir: string;
  let db: LocalDatabase;
  let scope: RedactionScope;
  // One surfaced leak: the on-disk transcript artifact and the raw key it holds,
  // paired with the raw-free masked summary the frame carries for it. Kept as one
  // object per leak so the displayed row and the file redaction acts on never drift.
  let leaks: { filePath: string; raw: string; finding: MaskedSecretFinding }[];

  const maskedFindings = (): MaskedSecretFinding[] => leaks.map((l) => l.finding);

  // The persisted calibration frame the loader reads back — built through the same
  // frameCalibration → frameJsonBlock path the wizard writes, so the loader's real
  // read boundary is exercised over frame-shaped input, not hand-built JSON.
  function persistedFrame(): string {
    return frameJsonBlock(frameCalibration(preview, maskedFindings()).frame);
  }

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-batched-transcripts-'));
    base = mkdtempSync(join(tmpdir(), 'aka-batched-store-'));
    workingDir = mkdtempSync(join(tmpdir(), 'aka-batched-cwd-'));
    // The real local store openLocalDatabase(dataDir) opens — the same one onboard.ts
    // and the enforcement path use. Its policies repo is the enforcement store.
    db = openLocalDatabase(join(base, 'data'));
    scope = { artifactRoots: [transcriptRoot] };

    // Three transcript artifacts, each holding one raw leaked key, plus the masked
    // per-finding summary the frame carries for it — the finding's where-found points
    // at the real artifact, tying the displayed row to the file redaction acts on.
    leaks = RAW_KEYS.map((raw, i) => {
      const filePath = join(transcriptRoot, `session-${String(i)}.jsonl`);
      writeFileSync(filePath, `{"content":"leaked ${raw} in an old prompt"}`);
      return {
        filePath,
        raw,
        finding: {
          provider: 'aws',
          maskedToken: MASKED_TOKEN,
          where: { filePath },
          // Validity is unverifiable under the no-network OSS constraint, so the loader
          // emits 'unknown' — the honest default, never a blanket 'still valid'.
          state: 'unknown',
        },
      };
    });
  });

  afterEach(() => {
    db.close();
    for (const dir of [transcriptRoot, base, workingDir]) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('step 1 — presents ONE batch of the 3 surfaced secret findings with the full decision layout, exactly four options, PII excluded, no "case"', () => {
    // The backfill's secret summaries are loaded from the persisted frame — read,
    // not synthesized — and the PII hit is excluded at the load: the frame genuinely
    // records pii activity, but only the 3 secret summaries reach the flow.
    const frame = frameCalibration(preview, maskedFindings()).frame;
    expect(frame.findingKinds.map((k) => k.category)).toContain('pii');
    const loaded = loadSecretLeakFindings(() => persistedFrame());
    expect(loaded).toEqual(maskedFindings());
    expect(loaded).toHaveLength(3);

    // One decision moment over the whole set — N templated over the real 3 findings,
    // no unverifiable 'still valid' claim in the copy.
    const decision = presentBatchedRemediation(loaded ?? [], FIRST_RUN);
    if (decision.kind !== 'decision')
      throw new Error(`expected a decision, got '${decision.kind}'`);
    expect(decision.secretCount).toBe(3);
    expect(decision.prompt).toContain('3 live keys are sitting in old transcripts');
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

    // The full decision layout, rendered against the REAL installed command registry so
    // the chaining line names only a secret-scan command the plugin actually registers.
    const registry = readRegisteredCommands();
    const layout = renderRemediationDecision(loaded ?? [], 0, registry);

    // The provider/token/where/state finding table — masked tokens and each
    // finding's honest 'unknown' state, one row per surfaced artifact.
    expect(layout).toContain('PROVIDER');
    expect(layout).toContain('TOKEN');
    expect(layout).toContain('STATE');
    expect(layout).toContain(MASKED_TOKEN);
    for (const { filePath } of leaks) expect(layout).toContain(filePath);
    expect(layout).toContain('unknown');
    expect(layout).not.toContain('still valid');

    // No RAW key ever crosses into the layout — the raw-free boundary, proven end
    // to end (the loaded findings carry only masked tokens, so the render cannot emit raw).
    for (const { raw } of leaks) {
      expect(MASKED_TOKEN).not.toEqual(raw);
      expect(layout).not.toContain(raw);
    }

    // The most-exposed-first recommendation line, verbatim.
    expect(layout).toContain("I'd redact them and get you rotating, most-exposed first");

    // The closing chaining line names the registered secret-scan continuation
    // (today /aka:scan) — resolved through the registry, never an unregistered command.
    const scanCommand = selectSecretScanContinuation(registry);
    expect(layout).toContain(`run ${scanCommand}`);

    // The word 'case' appears in no user-facing copy — not the prompt, not an
    // option label, not the rendered layout.
    for (const s of [decision.prompt, ...decision.options.map((o) => o.label), layout]) {
      expect(s.toLowerCase()).not.toContain('case');
    }
  });

  it('step 2 — "Redact only" redacts the transcript artifacts, then the standing-posture palette persists secret→Redact to the policies store', async () => {
    loadSecretLeakFindings(() => persistedFrame());

    // The raw values recovered from the still-on-disk artifacts, paired with the
    // finding's where-found — the redaction targets the 'Redact only' path strikes.
    const targets: RedactionTarget[] = leaks.map((l) => ({
      where: l.finding.where,
      rawValue: l.raw,
    }));

    // Route 'Redact only' with the REAL redaction mechanism bound; the posture writer
    // is present but must never be invoked on this path.
    const setStandingRedactPosture = vi.fn(() => writeStandingSecretPosture('redact', db.policies));
    const outcome = routeRemediationOption('redact-only', {
      redact: () => redactLeakedKeys(targets, scope),
      setStandingRedactPosture,
    });

    // It redacted the 3 real transcript keys and nothing more — no posture write,
    // no rotation-checklist deliverable.
    expect(outcome).toEqual({ kind: 'redacted', withRotationChecklist: false, redactedKeys: 3 });
    expect(setStandingRedactPosture).not.toHaveBeenCalled();
    for (const { filePath, raw } of leaks) {
      const after = readFileSync(filePath, 'utf8');
      expect(after).not.toContain(raw);
      expect(after).toContain('[REDACTED:SECRET]');
    }
    expect(existsSync(join(workingDir, 'rotation-checklist.md'))).toBe(false);

    // The standing-posture step then offers exactly Redact / Warn / Block / Monitor.
    const c3 = presentStandingSecretPosture();
    expect(c3.prompt).toContain("Set the 'secret' posture");
    expect(c3.options.map((o) => o.level)).toEqual(['redact', 'warn', 'block', 'monitor']);
    expect(c3.options.map((o) => o.label)).toEqual(['Redact', 'Warn', 'Block', 'Monitor']);

    // The user selects Redact: the standing 'secret'→Redact posture persists via
    // applyCategoryPosture to the REAL policies store (the enforcement store).
    const result = writeStandingSecretPosture('redact', db.policies);
    expect(result).toEqual({ persisted: true, level: 'redact' });

    // The posture is readable back from the enforcement store, so future secret
    // detections are governed by it.
    expect(db.policies.getCategoryAction('secret')).toBe('redact');
    const rows = await db.policies.readPolicies();
    const secretRow = rows.find((p) => (p.target as { category?: string }).category === 'secret');
    expect(secretRow?.action).toBe('redact');

    // The write landed in the policies store, NOT settings.json: only the DB store
    // was opened; no settings.json was ever written under the base.
    expect(existsSync(join(base, 'settings', 'settings.json'))).toBe(false);
  });

  it('step 3 — a fresh run choosing "Set \'secret\' to redact" persists secret→Redact with no artifact redacted and no deliverable', () => {
    // A separate fresh run: this test opens its own store (db, per beforeEach) with
    // no redaction having occurred. The store seeds the recommended default ('warn')
    // for 'secret' on open, so the standing Redact choice below is an observable
    // change from that baseline, not a coincidental match.
    expect(db.policies.getCategoryAction('secret')).toBe('warn');

    // At the remediation decision the user chooses the shortcut. The redaction mechanism is bound but must
    // never fire, and the posture writer targets the real policies store.
    const redact = vi.fn(() => redactLeakedKeys([], scope));
    const outcome = routeRemediationOption('set-secret-redact', {
      redact,
      setStandingRedactPosture: () => writeStandingSecretPosture('redact', db.policies),
    });

    // The shortcut wrote posture and nothing else: no artifact redacted (the redaction
    // mechanism was never invoked) and no deliverable generated.
    expect(outcome).toEqual({ kind: 'posture-set', posture: { persisted: true, level: 'redact' } });
    expect(redact).not.toHaveBeenCalled();
    expect(existsSync(join(workingDir, 'rotation-checklist.md'))).toBe(false);
    // The transcript artifacts are byte-identical — the shortcut path touches no file.
    for (const { filePath, raw } of leaks) {
      expect(readFileSync(filePath, 'utf8')).toContain(raw);
    }

    // The 'secret' posture is Redact in the policies store — the standing choice on
    // the shortcut path, exactly as on the 'Redact only' → standing-posture path.
    expect(db.policies.getCategoryAction('secret')).toBe('redact');
  });
});
