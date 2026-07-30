import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding } from '@akasecurity/persistence';
import { createVaultGlue, type VaultGlue } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { scrubTranscriptTail, type TailScrubDeps } from '../../src/history/tail-scrub.ts';
import type { RedactionScope } from '../../src/remediation/redact.ts';

// Canonical test AWS access-key id, composed at runtime so the repo's own secret
// scan does not flag this test file (mirrors remediation/redact.test.ts).
const SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

const pointersIn = (text: string): string[] =>
  [...text.matchAll(pointerTokenScanner())].map((m) => m[0]);

describe('scrubTranscriptTail', () => {
  // A fake transcripts root (the scope's one artifact root), an out-of-scope
  // sibling, and a throwaway ~/.aka base holding the real vault.
  let transcriptRoot: string;
  let outsideRoot: string;
  let base: string;
  let scope: RedactionScope;
  let glue: VaultGlue;
  let deps: TailScrubDeps;

  const depsFor = (g: VaultGlue): TailScrubDeps => ({
    tokenizeText: (text) => g.tokenizeText(text),
    scope,
  });

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-transcripts-'));
    outsideRoot = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-outside-'));
    base = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-home-'));
    scope = { artifactRoots: [transcriptRoot] };
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
    );
    glue = createVaultGlue({ base });
    deps = depsFor(glue);
  });

  afterEach(() => {
    rmSync(transcriptRoot, { recursive: true, force: true });
    rmSync(outsideRoot, { recursive: true, force: true });
    rmSync(base, { recursive: true, force: true });
  });

  const transcriptFile = (name: string, content: string): string => {
    const dir = join(transcriptRoot, '-Users-me-project');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, name);
    writeFileSync(file, content);
    return file;
  };

  it('rewrites the secret line to a vault pointer and leaves the clean line byte-identical', async () => {
    const secretLine = `{"type":"user","text":"key ${SECRET} end"}`;
    const cleanLine = '{"type":"assistant","text":"all clear"}';
    const file = transcriptFile('session.jsonl', `${secretLine}\n${cleanLine}\n`);

    const result = await scrubTranscriptTail(file, deps);
    expect(result).toEqual({ rewritten: 1 });

    const after = readFileSync(file, 'utf8');
    expect(after).not.toContain(SECRET);
    expect(after.endsWith('\n')).toBe(true);

    const lines = after.split('\n');
    expect(lines).toHaveLength(3); // two records + trailing-newline terminator
    expect(lines[1]).toBe(cleanLine);
    expect(lines[2]).toBe('');

    // The secret span became a pointer, embedded in still-valid NDJSON.
    expect(pointersIn(lines[0] ?? '')).toHaveLength(1);
    for (const line of lines.slice(0, 2)) {
      expect(() => {
        JSON.parse(line);
      }).not.toThrow();
    }
    const parsed = JSON.parse(lines[0] ?? '') as { text: string };
    expect(parsed.text).toContain('[[aka:');
  });

  it('mints the SAME pointer for the same value across two lines', async () => {
    const file = transcriptFile(
      'repeat.jsonl',
      `{"text":"first ${SECRET}"}\n{"text":"again ${SECRET}"}\n`,
    );

    const result = await scrubTranscriptTail(file, deps);
    expect(result).toEqual({ rewritten: 2 });

    const [a, b] = readFileSync(file, 'utf8').split('\n');
    const pa = pointersIn(a ?? '');
    const pb = pointersIn(b ?? '');
    expect(pa).toHaveLength(1);
    expect(pb).toHaveLength(1);
    expect(pa[0]).toBe(pb[0]);
  });

  it('is idempotent: a second run rewrites nothing and leaves the file byte-identical', async () => {
    const file = transcriptFile('idem.jsonl', `{"text":"key ${SECRET}"}\n`);
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 1 });

    const afterFirst = readFileSync(file, 'utf8');
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 0 });
    expect(readFileSync(file, 'utf8')).toBe(afterFirst);
  });

  it('returns { rewritten: 0 } without writing when the file holds no secret', async () => {
    const content = '{"text":"nothing sensitive here"}\n';
    const file = transcriptFile('clean.jsonl', content);
    expect(await scrubTranscriptTail(file, deps)).toEqual({ rewritten: 0 });
    expect(readFileSync(file, 'utf8')).toBe(content);
  });

  it('refuses an out-of-scope path and leaves it byte-identical', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const outside = join(outsideRoot, 'not-a-transcript.jsonl');
    writeFileSync(outside, content);

    expect(await scrubTranscriptTail(outside, deps)).toBeNull();
    expect(readFileSync(outside, 'utf8')).toBe(content);
  });

  it('refuses a symlink inside the root that points outside it', async () => {
    const content = `{"text":"key ${SECRET}"}\n`;
    const target = join(outsideRoot, 'target.jsonl');
    writeFileSync(target, content);
    const link = join(transcriptRoot, 'link.jsonl');
    symlinkSync(target, link);

    expect(await scrubTranscriptTail(link, deps)).toBeNull();
    expect(readFileSync(target, 'utf8')).toBe(content);
  });

  it('returns null for an unreadable path without throwing', async () => {
    expect(await scrubTranscriptTail(join(transcriptRoot, 'missing.jsonl'), deps)).toBeNull();
  });

  // The fault posture when consent vanished mid-pass (the call site gates on
  // consent, so a consent-less glue is only reachable via revocation between
  // the gate and the scrub): the residue is destroyed one-way — rewritten, but
  // to the un-recoverable placeholder, never left raw and never vaulted.
  it('degrades one-way under a consent-less glue: redacted placeholder, no pointer', async () => {
    const noConsentBase = mkdtempSync(join(tmpdir(), 'aka-tail-scrub-noconsent-'));
    try {
      const degradedGlue = createVaultGlue({ base: noConsentBase });
      const file = transcriptFile('degraded.jsonl', `{"text":"key ${SECRET}"}\n`);

      expect(await scrubTranscriptTail(file, depsFor(degradedGlue))).toEqual({ rewritten: 1 });

      const after = readFileSync(file, 'utf8');
      expect(after).not.toContain(SECRET);
      expect(after).toContain('[REDACTED');
      expect(after).not.toContain('[[aka:');
    } finally {
      rmSync(noConsentBase, { recursive: true, force: true });
    }
  });
});
