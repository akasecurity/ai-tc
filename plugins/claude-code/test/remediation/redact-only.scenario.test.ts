import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { routeRemediationOption } from '../../src/remediation/chain.ts';
import {
  type RedactionScope,
  type RedactionTarget,
  redactLeakedKeys,
} from '../../src/remediation/redact.ts';
import { renderRedactionConfirmation } from '../../src/remediation/render.ts';

// Redaction acts only on transcript and temp artifacts.
//
// The integration seam: the remediation option router (`routeRemediationOption`) run
// with the REAL redaction mechanism (`redactLeakedKeys`) bound as its `redact`
// handler, over a fixture set of secret findings that reference BOTH transcript/
// temp artifacts AND ordinary project files. Choosing 'Redact only' must redact
// the in-scope artifacts, leave the project files byte-identical, generate no
// rotation-checklist.md deliverable, and report the real redacted-key count.

// Canonical test AWS access-key ids, composed at runtime so the repo's own secret
// scan does not flag this file (mirrors redact.test.ts and the journey harness).
const TRANSCRIPT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const SECOND_TRANSCRIPT_KEY = ['AKIA', '2E7HTNXKP4LMKD9V'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

describe("'Redact only' routes real redaction, acts only on transcript/temp artifacts", () => {
  // Two in-scope artifact roots (transcript + temp) and one out-of-scope project
  // root, plus a separate working directory where a rotation-checklist.md would
  // land if the option wrongly produced a deliverable — all distinct siblings so
  // the scope limit is structural, not coincidental.
  let transcriptRoot: string;
  let tempRoot: string;
  let projectRoot: string;
  let workingDir: string;
  let scope: RedactionScope;

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-redactonly-transcripts-'));
    tempRoot = mkdtempSync(join(tmpdir(), 'aka-redactonly-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-redactonly-project-'));
    workingDir = mkdtempSync(join(tmpdir(), 'aka-redactonly-cwd-'));
    scope = { artifactRoots: [transcriptRoot, tempRoot] };
  });

  afterEach(() => {
    for (const dir of [transcriptRoot, tempRoot, projectRoot, workingDir]) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('redacts transcript/temp artifacts, leaves project files untouched, writes no checklist, reports the real count', () => {
    // Two transcript artifacts and one temp artifact, each holding a leaked key.
    const projectDir = join(transcriptRoot, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    const secondTranscript = join(transcriptRoot, 'earlier.jsonl');
    writeFileSync(secondTranscript, `earlier leak ${SECOND_TRANSCRIPT_KEY} here`);

    const tempFile = join(tempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);

    // An ordinary project file referenced by a finding too — in-place redaction
    // of arbitrary project files is out of scope for this flow, so it must be
    // left byte-identical.
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);
    const projectListingBefore = readdirSync(projectRoot);

    // The findings reference BOTH in-scope artifacts AND the ordinary project file.
    const targets: RedactionTarget[] = [
      { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
      { where: { filePath: secondTranscript }, rawValue: SECOND_TRANSCRIPT_KEY },
      { where: { filePath: tempFile }, rawValue: TEMP_KEY },
      { where: { filePath: projectFile }, rawValue: PROJECT_KEY },
    ];

    // Route 'Redact only' with the REAL redaction mechanism bound as the handler,
    // scoped to the transcript/temp roots. The posture-write handler is present but
    // must never be invoked on this path.
    let postureWrites = 0;
    const outcome = routeRemediationOption('redact-only', {
      redact: () => redactLeakedKeys(targets, scope),
      setStandingRedactPosture: () => {
        postureWrites += 1;
        return { persisted: true, level: 'redact' };
      },
    });

    // The router redacted and nothing more — no checklist requested, no posture write.
    expect(outcome).toEqual({ kind: 'redacted', withRotationChecklist: false, redactedKeys: 3 });
    expect(postureWrites).toBe(0);
    if (outcome.kind !== 'redacted') throw new Error(`expected redacted, got '${outcome.kind}'`);

    // Leaked keys in the transcript/temp artifacts are redacted (no longer readable).
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');
    expect(readFileSync(secondTranscript, 'utf8')).not.toContain(SECOND_TRANSCRIPT_KEY);
    expect(readFileSync(tempFile, 'utf8')).not.toContain(TEMP_KEY);

    // The ordinary project file is byte-for-byte unchanged, key intact — only the
    // transcript/temp artifacts were modified.
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
    expect(readdirSync(projectRoot)).toEqual(projectListingBefore);

    // No rotation-checklist.md is generated anywhere: the 'Redact only' choice
    // redacts and nothing more (no deliverable). The router never received a
    // working directory to write into, so a checklist would only appear if the
    // path wrongly produced one.
    expect(existsSync(join(workingDir, 'rotation-checklist.md'))).toBe(false);
    expect(existsSync(join(projectRoot, 'rotation-checklist.md'))).toBe(false);
    expect(existsSync(join(transcriptRoot, 'rotation-checklist.md'))).toBe(false);

    // The confirmation reports the REAL redacted-key count.
    expect(renderRedactionConfirmation(outcome.redactedKeys)).toBe('✓ Redacted 3 keys');
  });

  it('reports the real count for a different fixture set — the confirmation is not hardcoded', () => {
    // A single in-scope transcript artifact plus an out-of-scope project file.
    const transcriptFile = join(transcriptRoot, 'session.jsonl');
    writeFileSync(transcriptFile, `only leak ${TRANSCRIPT_KEY}`);
    const projectFile = join(projectRoot, 'app.ts');
    writeFileSync(projectFile, `const key = '${PROJECT_KEY}';\n`);
    const projectBytesBefore = readFileSync(projectFile);

    const outcome = routeRemediationOption('redact-only', {
      redact: () =>
        redactLeakedKeys(
          [
            { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
            { where: { filePath: projectFile }, rawValue: PROJECT_KEY },
          ],
          scope,
        ),
      setStandingRedactPosture: () => ({ persisted: true, level: 'redact' }),
    });

    // Only the in-scope key was redacted, so the count is 1 and the confirmation
    // pluralizes over the real work — proving no literal '3'/'keys' drives it.
    expect(outcome).toEqual({ kind: 'redacted', withRotationChecklist: false, redactedKeys: 1 });
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    if (outcome.kind !== 'redacted') throw new Error(`expected redacted, got '${outcome.kind}'`);
    expect(renderRedactionConfirmation(outcome.redactedKeys)).toBe('✓ Redacted 1 key');
  });
});
