import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  platformRedactionScope,
  type RedactionScope,
  redactLeakedKeys,
  redactLeakedKeysDetailed,
} from '../../src/remediation/redact.ts';

// Canonical test AWS access-key ids, composed at runtime so the repo's own secret
// scan does not flag this test file (mirrors history/scan.test.ts and the journey
// harness). Their exact value is irrelevant to redaction — the module strikes a
// verbatim occurrence — only that they are distinct and long enough to be a
// meaningful match.
const TRANSCRIPT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

describe('redactLeakedKeys', () => {
  // Two in-scope artifact roots (transcript + temp) and one out-of-scope project
  // root, all distinct siblings under the OS temp dir — so the project root shares
  // no ancestry with an artifact root and the scope limit is a structural, not a
  // coincidental, boundary.
  let transcriptRoot: string;
  let tempRoot: string;
  let projectRoot: string;
  let scope: RedactionScope;

  beforeEach(() => {
    transcriptRoot = mkdtempSync(join(tmpdir(), 'aka-redact-transcripts-'));
    tempRoot = mkdtempSync(join(tmpdir(), 'aka-redact-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-redact-project-'));
    scope = { artifactRoots: [transcriptRoot, tempRoot] };
  });

  afterEach(() => {
    rmSync(transcriptRoot, { recursive: true, force: true });
    rmSync(tempRoot, { recursive: true, force: true });
    rmSync(projectRoot, { recursive: true, force: true });
  });

  it('redacts leaked keys in transcript and temp artifacts, returning the real count', () => {
    // A transcript artifact nested under the transcript root (projects/<slug>/*.jsonl).
    const projectDir = join(transcriptRoot, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const transcriptFile = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptFile, `{"content":"here is a key ${TRANSCRIPT_KEY} in a prompt"}`);

    // A temp artifact directly under the temp root.
    const tempFile = join(tempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);

    const count = redactLeakedKeys(
      [
        { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
        { where: { filePath: tempFile }, rawValue: TEMP_KEY },
      ],
      scope,
    );

    expect(count).toBe(2);

    // The leaked keys are no longer readable in either artifact.
    const transcriptAfter = readFileSync(transcriptFile, 'utf8');
    expect(transcriptAfter).not.toContain(TRANSCRIPT_KEY);
    expect(transcriptAfter).toContain('[REDACTED:SECRET]');

    const tempAfter = readFileSync(tempFile, 'utf8');
    expect(tempAfter).not.toContain(TEMP_KEY);
    expect(tempAfter).toContain('[REDACTED:SECRET]');
  });

  it('leaves ordinary project files byte-identical — the binding scope limit', () => {
    const transcriptFile = join(transcriptRoot, 'session.jsonl');
    writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY}`);

    // A finding references an ordinary project file too. It must never be touched:
    // in-place redaction of arbitrary project files is out of scope for this flow.
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);

    const count = redactLeakedKeys(
      [
        { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
        { where: { filePath: projectFile }, rawValue: PROJECT_KEY },
      ],
      scope,
    );

    // Only the transcript key was redacted; the project-file key is out of scope.
    expect(count).toBe(1);

    // The transcript artifact was redacted.
    expect(readFileSync(transcriptFile, 'utf8')).not.toContain(TRANSCRIPT_KEY);

    // The project file is byte-for-byte unchanged, key intact.
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
  });

  it('never writes outside the transcript/temp artifact set even for a full project batch', () => {
    // Every finding in this batch references an out-of-scope project file.
    const fileA = join(projectRoot, 'a.ts');
    const fileB = join(projectRoot, 'nested', 'b.ts');
    mkdirSync(join(projectRoot, 'nested'), { recursive: true });
    writeFileSync(fileA, `const key = '${PROJECT_KEY}';\n`);
    writeFileSync(fileB, `export const KEY = '${TEMP_KEY}';\n`);
    const bytesA = readFileSync(fileA);
    const bytesB = readFileSync(fileB);

    const count = redactLeakedKeys(
      [
        { where: { filePath: fileA }, rawValue: PROJECT_KEY },
        { where: { filePath: fileB }, rawValue: TEMP_KEY },
      ],
      scope,
    );

    expect(count).toBe(0);
    expect(readFileSync(fileA)).toEqual(bytesA);
    expect(readFileSync(fileB)).toEqual(bytesB);
  });

  it('redacts every occurrence of a key and counts only keys actually redacted', () => {
    // One artifact holds the same key twice; another in-scope artifact does not
    // hold its referenced key at all.
    const multi = join(transcriptRoot, 'multi.jsonl');
    writeFileSync(multi, `first ${TRANSCRIPT_KEY} middle ${TRANSCRIPT_KEY} last`);
    const absent = join(transcriptRoot, 'absent.jsonl');
    writeFileSync(absent, 'no secret in this transcript');

    const count = redactLeakedKeys(
      [
        { where: { filePath: multi }, rawValue: TRANSCRIPT_KEY },
        // In scope, but the referenced key is not present in the file.
        { where: { filePath: absent }, rawValue: TEMP_KEY },
      ],
      scope,
    );

    // The absent key was never actually redacted, so it is not counted.
    expect(count).toBe(1);

    const multiAfter = readFileSync(multi, 'utf8');
    expect(multiAfter).not.toContain(TRANSCRIPT_KEY);
    // BOTH occurrences were struck.
    expect(multiAfter.match(/\[REDACTED:SECRET\]/g)).toHaveLength(2);

    // The file whose key was absent is untouched.
    expect(readFileSync(absent, 'utf8')).toBe('no secret in this transcript');
  });

  it('counts every finding on a repeated value struck, not just the first', () => {
    // The same raw secret value appears twice in one transcript and is surfaced
    // as TWO findings (two targets sharing one rawValue). The first strike's
    // replaceAll clears every occurrence, so the second target's value is already
    // gone — it must still count as struck, never misreported as still exposed.
    const transcriptFile = join(transcriptRoot, 'repeated.jsonl');
    writeFileSync(transcriptFile, `one ${TRANSCRIPT_KEY} two ${TRANSCRIPT_KEY} done`);

    const targets = [
      { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
      { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
    ];
    const detail = redactLeakedKeysDetailed(targets, scope);

    // Both findings resolve on the single rewrite: counted and struck, so a
    // caller diffing its input against `struck` finds nothing left unredacted.
    expect(detail.redactedKeys).toBe(2);
    expect(detail.struck).toEqual(targets);
    expect(readFileSync(transcriptFile, 'utf8')).not.toContain(TRANSCRIPT_KEY);
  });

  it('the production default scope does not treat an arbitrary temp file as in-scope', () => {
    // Under the real platform default scope (transcripts dir only), a leaked key in
    // a file that merely lives under the OS temp dir is NOT redacted — proving the
    // shipped default never grants redaction over the whole OS temp tree.
    const strayFile = join(tempRoot, 'stray-under-tmp.txt');
    writeFileSync(strayFile, `stray ${TEMP_KEY} value`);
    const bytesBefore = readFileSync(strayFile);

    const count = redactLeakedKeys([{ where: { filePath: strayFile }, rawValue: TEMP_KEY }]);

    expect(count).toBe(0);
    expect(readFileSync(strayFile)).toEqual(bytesBefore);
    expect(readFileSync(strayFile, 'utf8')).toContain(TEMP_KEY);
    // Sanity: the default scope is transcripts-only, not the OS temp dir.
    expect(platformRedactionScope().artifactRoots).not.toContain(tmpdir());
  });

  it('a symlink inside an allowed root cannot redirect a write outside it', () => {
    // The leaked key lives in an ordinary project file OUTSIDE every root.
    const projectFile = join(projectRoot, 'secrets.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);

    // A symlink placed INSIDE an allowed artifact root points at that external
    // project file. A lexical prefix check would accept the symlink's path; the
    // real-path containment check must reject it so the write never escapes.
    const symlinkInRoot = join(transcriptRoot, 'escape.jsonl');
    symlinkSync(projectFile, symlinkInRoot);

    const count = redactLeakedKeys(
      [{ where: { filePath: symlinkInRoot }, rawValue: PROJECT_KEY }],
      scope,
    );

    expect(count).toBe(0);
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
  });

  it('is best-effort per file: a missing artifact does not abort the batch', () => {
    // One in-scope artifact exists and holds its key; another in-scope target
    // references a path that does not exist on disk.
    const present = join(transcriptRoot, 'present.jsonl');
    writeFileSync(present, `leaked ${TRANSCRIPT_KEY} here`);
    const missing = join(tempRoot, 'never-written.txt');

    const count = redactLeakedKeys(
      [
        // The missing target is listed first, so a batch-aborting throw would leave
        // the present artifact un-redacted.
        { where: { filePath: missing }, rawValue: TEMP_KEY },
        { where: { filePath: present }, rawValue: TRANSCRIPT_KEY },
      ],
      scope,
    );

    // The missing artifact contributes nothing; the present one is still redacted.
    expect(count).toBe(1);
    expect(readFileSync(present, 'utf8')).not.toContain(TRANSCRIPT_KEY);
    expect(readFileSync(present, 'utf8')).toContain('[REDACTED:SECRET]');
  });

  describe('.aka-redact.tmp cleanup', () => {
    // Entries left behind matching the atomic-write sibling-temp-file naming.
    function orphanedTmpEntries(dir: string): string[] {
      return readdirSync(dir).filter((entry) => entry.endsWith('.aka-redact.tmp'));
    }

    it('leaves no .aka-redact.tmp sibling after a successful redaction', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      expect(count).toBe(1);
      expect(readFileSync(transcriptFile, 'utf8')).toContain('[REDACTED:SECRET]');
      // The rename consumed the temp file — no orphan sibling remains.
      expect(orphanedTmpEntries(transcriptRoot)).toEqual([]);
    });

    it('leaves no .aka-redact.tmp orphan and the original intact when the atomic write fails', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      const originalContent = `leaked ${TRANSCRIPT_KEY} here`;
      writeFileSync(transcriptFile, originalContent);

      // Pre-create a DIRECTORY at the exact sibling temp path the atomic write
      // uses, so `writeFileSync(tmpPath, content)` throws EISDIR instead of
      // writing — a deterministic, OS-level way to force the write/rename step
      // to fail without touching the original file at all.
      const tmpPath = `${transcriptFile}.aka-redact.tmp`;
      mkdirSync(tmpPath);

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      // The write failed, so nothing was redacted or counted.
      expect(count).toBe(0);
      // The cleanup catch removed the tmp entry — even though it turned out to be
      // a directory rather than a partially written file — so no orphan survives.
      expect(orphanedTmpEntries(transcriptRoot)).toEqual([]);
      // The atomic-write guarantee: the original artifact is untouched.
      expect(readFileSync(transcriptFile, 'utf8')).toBe(originalContent);
    });
  });
});
