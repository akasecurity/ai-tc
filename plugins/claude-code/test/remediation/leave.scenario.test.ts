import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import type { MaskedSecretFinding, RemediationEntryContext } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { presentBatchedRemediation, routeRemediationOption } from '../../src/remediation/chain.ts';
import { writeStandingSecretPosture } from '../../src/remediation/posture.ts';
import {
  type RedactionScope,
  type RedactionTarget,
  redactLeakedKeys,
} from '../../src/remediation/redact.ts';

// 'Leave' exits the remediation flow without any changes.
//
// The integration seam (mirrors redact-only.scenario.test.ts): the
// batched remediation decision is presented over live-key findings (the precondition), then
// the option router (`routeRemediationOption`) is run with the REAL redaction
// mechanism and the REAL standing-posture writer bound as its handlers over a REAL
// local store and on-disk transcript/temp artifacts. Choosing 'Leave' must return a
// clean-exit outcome and leave the wired-in capabilities' targets — the artifacts,
// the policies store, settings.json, and an ordinary project file — untouched.
//
// The routing guarantee itself (which handler each option invokes, and which it
// leaves alone) is proven at the unit seam in chain.test.ts; this scenario walks the
// precondition→choose-Leave→observable path with the real capabilities wired in so
// the scenario's stated observables are asserted over real artifacts and a real store.

// Canonical AWS access-key ids composed at runtime so the repo's own secret scan
// does not flag this file (mirrors redact.test.ts and the other scenario tests).
const TRANSCRIPT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

const MASKED_TOKEN = 'AKIA****************';
const FIRST_RUN: RemediationEntryContext = { entrySource: 'first-run' };

describe('Leave exits the remediation flow with zero side effects', () => {
  // In-scope transcript + temp artifact roots (redaction would act here if it ran),
  // an out-of-scope project root standing in for the repo working tree, the real
  // local-store base (settings/ + data/aka.db), and a working dir where a
  // rotation-checklist.md would land if the path wrongly produced a deliverable.
  let transcriptRoot: string;
  let tempRoot: string;
  let projectRoot: string;
  let base: string;
  let workingDir: string;
  let db: LocalDatabase;
  let scope: RedactionScope;

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-leave-transcripts-'));
    tempRoot = mkdtempSync(join(tmpdir(), 'aka-leave-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-leave-project-'));
    base = mkdtempSync(join(tmpdir(), 'aka-leave-store-'));
    workingDir = mkdtempSync(join(tmpdir(), 'aka-leave-cwd-'));
    // The real local store openLocalDatabase(dataDir) opens — the same one onboard.ts
    // and the enforcement path use. Its policies repo is the enforcement store.
    db = openLocalDatabase(join(base, 'data'));
    scope = { artifactRoots: [transcriptRoot, tempRoot] };
  });

  afterEach(() => {
    db.close();
    for (const dir of [transcriptRoot, tempRoot, projectRoot, base, workingDir]) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves the artifacts, the store, settings.json, and the project tree untouched', () => {
    // Live-key findings: two in-scope artifacts (a transcript and a temp scratch
    // file) plus an ordinary project file — each holding a real leaked key that
    // redaction WOULD strike if it ran.
    const transcriptFile = join(transcriptRoot, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);
    const tempFile = join(tempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);

    const findings: MaskedSecretFinding[] = [
      {
        provider: 'aws',
        maskedToken: MASKED_TOKEN,
        where: { filePath: transcriptFile },
        state: 'unknown',
      },
      {
        provider: 'aws',
        maskedToken: MASKED_TOKEN,
        where: { filePath: tempFile },
        state: 'unknown',
      },
      {
        provider: 'aws',
        maskedToken: MASKED_TOKEN,
        where: { filePath: projectFile },
        state: 'unknown',
      },
    ];

    // The redaction targets the 'Redact' options WOULD strike, bound to the real
    // mechanism below — present only to prove 'Leave' never invokes them.
    const targets: RedactionTarget[] = [
      { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
      { where: { filePath: tempFile }, rawValue: TEMP_KEY },
      { where: { filePath: projectFile }, rawValue: PROJECT_KEY },
    ];

    // Precondition: the batched remediation decision is presented over the live-key findings,
    // with 'Leave' among the exactly-four options.
    const decision = presentBatchedRemediation(findings, FIRST_RUN);
    if (decision.kind !== 'decision')
      throw new Error(`expected a decision, got '${decision.kind}'`);
    expect(decision.secretCount).toBe(3);
    expect(decision.options.map((o) => o.id)).toContain('leave');

    // Baseline: the store seeds 'warn' for 'secret' on open — a posture write would be
    // an observable change from it.
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    const transcriptBefore = readFileSync(transcriptFile);
    const tempBefore = readFileSync(tempFile);
    const projectBefore = readFileSync(projectFile);
    const projectListingBefore = readdirSync(projectRoot);

    // Action: the user chooses 'Leave'. The REAL redaction + REAL posture writer are
    // bound (wrapped in spies), so an errant call would truly mutate on-disk state.
    const redact = vi.fn(() => redactLeakedKeys(targets, scope));
    const setStandingRedactPosture = vi.fn(() => writeStandingSecretPosture('redact', db.policies));
    const outcome = routeRemediationOption('leave', { redact, setStandingRedactPosture });

    // The flow exits cleanly and the session continues — a clean-exit outcome, not a throw.
    expect(outcome).toEqual({ kind: 'left' });

    // The load-bearing routing guarantee: neither side-effecting capability was
    // invoked (also proven directly in chain.test.ts). The observable assertions
    // below confirm the wired-in capabilities' real targets are unchanged as a result.
    expect(redact).not.toHaveBeenCalled();
    expect(setStandingRedactPosture).not.toHaveBeenCalled();

    // No transcript/temp artifact is modified — byte-identical, leaked keys still present.
    expect(readFileSync(transcriptFile)).toEqual(transcriptBefore);
    expect(readFileSync(transcriptFile, 'utf8')).toContain(TRANSCRIPT_KEY);
    expect(readFileSync(tempFile)).toEqual(tempBefore);
    expect(readFileSync(tempFile, 'utf8')).toContain(TEMP_KEY);

    // No rotation-checklist.md deliverable is generated in the working directory.
    expect(existsSync(join(workingDir, 'rotation-checklist.md'))).toBe(false);

    // No posture is written: the policies store is untouched — 'secret' still at the
    // seeded 'warn' baseline, and settings.json was never created.
    expect(db.policies.getCategoryAction('secret')).toBe('warn');
    expect(existsSync(join(base, 'settings', 'settings.json'))).toBe(false);

    // The repo working tree is unchanged: the ordinary project file is byte-identical
    // with its key intact, and its directory listing did not move.
    expect(readFileSync(projectFile)).toEqual(projectBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
    expect(readdirSync(projectRoot)).toEqual(projectListingBefore);
  });
});
