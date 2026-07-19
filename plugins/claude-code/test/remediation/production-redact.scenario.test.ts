import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type { MaskedSecretFinding } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { redactSurfacedSecrets } from '../../src/remediation/surfaced-redact.ts';
import { deriveProvider } from '../../src/triage/surfaced-secrets.ts';

// The PRODUCTION redaction adapter: unlike `redactLeakedKeys`,
// which trusts whatever `RedactionScope` a caller builds, `redactSurfacedSecrets`
// derives its own transcript/temp artifact scope and refuses a caller's attempt
// to widen it into a project working tree. This suite proves both halves: a
// legitimately-supplied temp root is honoured (genuine transcript/temp artifacts
// are redacted), and a project root passed off as the temp scope is rejected —
// the project file is left byte-identical no matter how it is offered.

const AWS_RULE_ID = 'secrets/aws-access-key';
const PROVIDER = deriveProvider(AWS_RULE_ID);

// Canonical test AWS access-key ids, composed at runtime so the repo's own secret
// scan does not flag this file (mirrors redact.test.ts and redact-only.scenario.test.ts).
// Each passes the real detection engine's entropy validator (proven already by
// history/scan.test.ts, which runs the same values through the same engine).
const TRANSCRIPT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

function findingFor(filePath: string, rawValue: string): MaskedSecretFinding {
  return {
    provider: PROVIDER,
    maskedToken: safeMaskedMatch(rawValue),
    where: { filePath },
    state: 'unknown',
  };
}

describe('redactSurfacedSecrets — the production redaction adapter', () => {
  // A throwaway HOME (transcripts live at `<home>/.claude/projects/...`, exactly
  // what `transcriptsDir` derives) and a throwaway `~/.aka` base for the runtime's
  // local store — so this suite never touches the developer's real machine state.
  let home: string;
  let dataDirBase: string;
  // A genuinely bounded scratch directory a caller could legitimately name as its
  // own temp root, and a directory standing in for a real project working tree
  // (marked with a `.git` entry, exactly like a real repo root) that a caller
  // might — wrongly — try to pass off as that same temp root.
  let legitTempRoot: string;
  let projectRoot: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-prodredact-home-'));
    dataDirBase = mkdtempSync(join(tmpdir(), 'aka-prodredact-store-'));
    legitTempRoot = mkdtempSync(join(tmpdir(), 'aka-prodredact-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-prodredact-project-'));
    mkdirSync(join(projectRoot, '.git'));
  });

  afterEach(() => {
    for (const dir of [home, dataDirBase, legitTempRoot, projectRoot]) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('redacts genuine transcript and temp artifacts when a legitimate temp root is supplied', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    const tempFile = join(legitTempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);

    const findings = [findingFor(transcriptFile, TRANSCRIPT_KEY), findingFor(tempFile, TEMP_KEY)];

    const count = await redactSurfacedSecrets(findings, {
      home,
      dataDirBase,
      tempRoot: legitTempRoot,
    });

    expect(count).toBe(2);
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');
    const tempAfter = readFileSync(tempFile, 'utf8');
    expect(tempAfter).not.toContain(TEMP_KEY);
    expect(tempAfter).toContain('[REDACTED:SECRET]');
  });

  it('rejects a project root offered as the temp scope — no project file is redacted, transcript artifacts still are, and the count reflects only real strikes', async () => {
    const projectDir = join(home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"a key ${TRANSCRIPT_KEY} in a prompt"}`);

    // The "temp root" this call supplies is actually a project working tree
    // (marked with `.git`) — an attempt to widen redaction beyond the
    // transcript/temp artifact class by mislabeling it.
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);
    const projectListingBefore = readdirSync(projectRoot);

    const findings = [
      findingFor(transcriptFile, TRANSCRIPT_KEY),
      findingFor(projectFile, PROJECT_KEY),
    ];

    const count = await redactSurfacedSecrets(findings, {
      home,
      dataDirBase,
      tempRoot: projectRoot,
    });

    // Only the genuine transcript artifact was redacted — the project-root scope
    // was refused outright, not partially honoured.
    expect(count).toBe(1);
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');

    // The project file is byte-for-byte unchanged and its directory listing
    // untouched — the rejected scope never widened redaction into it.
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
    expect(readdirSync(projectRoot)).toEqual(projectListingBefore);
  });

  it('returns 0 and touches nothing for an empty findings set', async () => {
    const count = await redactSurfacedSecrets([], { home, dataDirBase });
    expect(count).toBe(0);
  });
});
