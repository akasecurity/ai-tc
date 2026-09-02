import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
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

  it('a symlink inside an allowed root cannot redirect a write outside it', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
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

  describe('pre-resolved replacements (recoverable vault pointers)', () => {
    // A well-formed pointer-shaped replacement, as the async vault caller would
    // pre-resolve. Its exact shape is irrelevant to this module — any non-raw
    // string a caller maps is substituted verbatim.
    const POINTER = `[[aka:secret:AE.${'A'.repeat(26)}.${'2'.repeat(16)}]]`;

    it('substitutes the mapped replacement, removes the raw value, and leaves every other byte identical', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      const before = `line one untouched\n{"content":"key ${TRANSCRIPT_KEY} here"}\nline three untouched\n`;
      writeFileSync(transcriptFile, before);

      const detail = redactLeakedKeysDetailed(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
        new Map([[TRANSCRIPT_KEY, POINTER]]),
      );

      expect(detail.redactedKeys).toBe(1);
      expect(detail.pointeredKeys).toBe(1);
      const after = readFileSync(transcriptFile, 'utf8');
      // The rewrite is exactly the raw value's occurrences swapped for the
      // pointer — no placeholder, no other byte touched.
      expect(after).toBe(before.replaceAll(TRANSCRIPT_KEY, POINTER));
      expect(after).not.toContain(TRANSCRIPT_KEY);
      expect(after).not.toContain('[REDACTED:SECRET]');
    });

    it('a value without a map entry still strikes one-way, and the counts separate the two', () => {
      const transcriptFile = join(transcriptRoot, 'mixed.jsonl');
      writeFileSync(transcriptFile, `pointered ${TRANSCRIPT_KEY} struck ${TEMP_KEY} end`);

      const detail = redactLeakedKeysDetailed(
        [
          { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
          { where: { filePath: transcriptFile }, rawValue: TEMP_KEY },
        ],
        scope,
        new Map([[TRANSCRIPT_KEY, POINTER]]),
      );

      expect(detail.redactedKeys).toBe(2);
      expect(detail.pointeredKeys).toBe(1);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).toBe(`pointered ${POINTER} struck [REDACTED:SECRET] end`);
    });

    it('a map entry equal to the raw value itself falls back to the one-way placeholder', () => {
      const transcriptFile = join(transcriptRoot, 'self-map.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);

      const detail = redactLeakedKeysDetailed(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
        new Map([[TRANSCRIPT_KEY, TRANSCRIPT_KEY]]),
      );

      // The self-mapping entry is never honoured: the value is struck one-way
      // and not counted as pointered.
      expect(detail.redactedKeys).toBe(1);
      expect(detail.pointeredKeys).toBe(0);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).toBe('leaked [REDACTED:SECRET] here');
    });

    it('a map entry CONTAINING the raw value falls back to the one-way placeholder', () => {
      const transcriptFile = join(transcriptRoot, 'containing-map.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);

      // A candidate that embeds the raw value would leave the secret readable
      // while reporting it redacted — it must never be honoured.
      const detail = redactLeakedKeysDetailed(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
        new Map([[TRANSCRIPT_KEY, `wrapped(${TRANSCRIPT_KEY})`]]),
      );

      expect(detail.redactedKeys).toBe(1);
      expect(detail.pointeredKeys).toBe(0);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).toBe('leaked [REDACTED:SECRET] here');
      expect(after).not.toContain(TRANSCRIPT_KEY);
    });

    it("a '$&' map entry falls back to the placeholder — the match is never re-inserted", () => {
      const transcriptFile = join(transcriptRoot, 'dollar-map.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);

      // '$&' is the replace-pattern sequence for "the matched substring": fed
      // to a replace-family API it would rewrite the secret with itself and
      // count it redacted. The sweep must refuse it and strike one-way.
      const detail = redactLeakedKeysDetailed(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
        new Map([[TRANSCRIPT_KEY, '$&']]),
      );

      expect(detail.redactedKeys).toBe(1);
      expect(detail.pointeredKeys).toBe(0);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).toBe('leaked [REDACTED:SECRET] here');
      expect(after).not.toContain(TRANSCRIPT_KEY);
    });

    it('an empty map behaves byte-identically to no map at all', () => {
      const withMap = join(transcriptRoot, 'with-empty-map.jsonl');
      const without = join(transcriptRoot, 'without-map.jsonl');
      const content = `leaked ${TRANSCRIPT_KEY} twice ${TRANSCRIPT_KEY}`;
      writeFileSync(withMap, content);
      writeFileSync(without, content);

      const mapDetail = redactLeakedKeysDetailed(
        [{ where: { filePath: withMap }, rawValue: TRANSCRIPT_KEY }],
        scope,
        new Map(),
      );
      const plainDetail = redactLeakedKeysDetailed(
        [{ where: { filePath: without }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      expect(mapDetail.redactedKeys).toBe(plainDetail.redactedKeys);
      expect(mapDetail.pointeredKeys).toBe(0);
      expect(plainDetail.pointeredKeys).toBe(0);
      expect(readFileSync(withMap)).toEqual(readFileSync(without));
    });

    it('counts every finding on a repeated pointered value, same as the one-way sibling rule', () => {
      const transcriptFile = join(transcriptRoot, 'repeated-pointered.jsonl');
      writeFileSync(transcriptFile, `one ${TRANSCRIPT_KEY} two ${TRANSCRIPT_KEY} done`);

      const targets = [
        { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
        { where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY },
      ];
      const detail = redactLeakedKeysDetailed(targets, scope, new Map([[TRANSCRIPT_KEY, POINTER]]));

      // Both findings resolve on the single rewrite and both count pointered —
      // one raw value has exactly one replacement across the sweep.
      expect(detail.redactedKeys).toBe(2);
      expect(detail.pointeredKeys).toBe(2);
      expect(detail.struck).toEqual(targets);
      const after = readFileSync(transcriptFile, 'utf8');
      expect(after).toBe(`one ${POINTER} two ${POINTER} done`);
    });
  });

  describe('.aka-redact.tmp cleanup', () => {
    // A pid no platform can hand out: Linux caps `pid_max` at 2^22 and macOS at
    // 99999, so `kill(pid, 0)` answers ESRCH here rather than racing some real
    // process. That makes "a killed earlier run" a fixture rather than a gamble
    // on pid reuse.
    const DEAD_PID = 1_073_741_823;

    // The temp path this module mints for `artifact` when it runs as `pid`.
    function tempName(artifact: string, pid: number): string {
      return `${artifact}.${String(pid)}.aka-redact.tmp`;
    }

    // Entries left behind matching the atomic-write sibling-temp-file naming.
    function orphanedTmpEntries(dir: string): string[] {
      return readdirSync(dir)
        .filter((entry) => entry.endsWith('.aka-redact.tmp'))
        .sort();
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
      // uses. The sweep leaves it (a directory is not something this module
      // wrote) and the exclusive create then refuses to publish through it — a
      // deterministic, OS-level way to force the write/rename step to fail
      // without touching the original file at all.
      const tmpPath = tempName(transcriptFile, process.pid);
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

    it('sweeps the copy a killed earlier run stranded beside the artifact', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);
      // A temp a run that died between the write and the rename left behind: a
      // whole copy of the transcript that nothing else would ever remove.
      const stranded = tempName(transcriptFile, DEAD_PID);
      writeFileSync(stranded, `stranded copy ${TRANSCRIPT_KEY} here`);

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      expect(count).toBe(1);
      expect(existsSync(stranded)).toBe(false);
      expect(orphanedTmpEntries(transcriptRoot)).toEqual([]);
    });

    it('sweeps a stranded copy even when this pass strikes nothing', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      const originalContent = 'nothing leaked here';
      writeFileSync(transcriptFile, originalContent);
      const stranded = tempName(transcriptFile, DEAD_PID);
      writeFileSync(stranded, `stranded copy ${TRANSCRIPT_KEY} here`);

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      // The artifact stays byte-identical — the sweep runs on every artifact the
      // pass opens, not only on the ones it goes on to rewrite.
      expect(count).toBe(0);
      expect(readFileSync(transcriptFile, 'utf8')).toBe(originalContent);
      expect(existsSync(stranded)).toBe(false);
    });

    it("leaves a live run's temp file alone", () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);
      // The parent of this test process is alive by construction, so its temp is
      // work in progress rather than a leftover — sweeping it would delete
      // another run's bytes out from under its own rename.
      const live = tempName(transcriptFile, process.ppid);
      writeFileSync(live, 'in flight');

      redactLeakedKeys([{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }], scope);

      expect(readFileSync(live, 'utf8')).toBe('in flight');
    });

    it('never removes a sibling it did not name', () => {
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);
      const bystanders = [
        // The pid-free shape: nothing this module mints.
        `${transcriptFile}.aka-redact.tmp`,
        `${transcriptFile}.notapid.aka-redact.tmp`,
        `${transcriptFile}. 7.aka-redact.tmp`,
        // A temp belonging to a DIFFERENT artifact in the same directory.
        tempName(join(transcriptRoot, 'other.jsonl'), DEAD_PID),
        // The suffix has to end the name, not merely appear in it.
        `${tempName(transcriptFile, DEAD_PID)}.bak`,
      ];
      for (const path of bystanders) writeFileSync(path, 'not ours');

      redactLeakedKeys([{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }], scope);

      for (const path of bystanders) expect(existsSync(path)).toBe(true);
    });

    it('refuses to publish through a symlink planted at its temp path', (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
      }
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      const originalContent = `leaked ${TRANSCRIPT_KEY} here`;
      writeFileSync(transcriptFile, originalContent);
      // A file outside every artifact root, standing in for whatever a planted
      // link would aim at. Following the link would copy this artifact's whole
      // contents over it and then rename the link itself over the artifact.
      const outside = join(projectRoot, 'notes.txt');
      writeFileSync(outside, 'untouched');
      symlinkSync(outside, tempName(transcriptFile, process.pid));

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      // Doubt at the temp path comes out as "did nothing": no write, no count.
      expect(count).toBe(0);
      expect(readFileSync(outside, 'utf8')).toBe('untouched');
      expect(readFileSync(transcriptFile, 'utf8')).toBe(originalContent);
      expect(lstatSync(transcriptFile).isSymbolicLink()).toBe(false);
      expect(orphanedTmpEntries(transcriptRoot)).toEqual([]);
    });

    it('clears a leftover carrying its own pid rather than writing through it', (ctx) => {
      if (process.platform === 'win32') ctx.skip('POSIX permission bits');
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`, { mode: 0o600 });
      // The one temp path this process would pick, left behind by an earlier
      // process that happened to carry the same pid. Writing through it would
      // publish the artifact with the leftover's permission bits, since a write
      // applies its mode only when it CREATES the file.
      writeFileSync(tempName(transcriptFile, process.pid), 'stale', { mode: 0o644 });

      const count = redactLeakedKeys(
        [{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }],
        scope,
      );

      expect(count).toBe(1);
      expect(readFileSync(transcriptFile, 'utf8')).toContain('[REDACTED:SECRET]');
      expect(statSync(transcriptFile).mode & 0o777).toBe(0o600);
      expect(orphanedTmpEntries(transcriptRoot)).toEqual([]);
    });

    it('publishes the redacted artifact with the permission bits it had', (ctx) => {
      if (process.platform === 'win32') ctx.skip('POSIX permission bits');
      const transcriptFile = join(transcriptRoot, 'session.jsonl');
      writeFileSync(transcriptFile, `leaked ${TRANSCRIPT_KEY} here`);
      chmodSync(transcriptFile, 0o600);

      redactLeakedKeys([{ where: { filePath: transcriptFile }, rawValue: TRANSCRIPT_KEY }], scope);

      // The rewrite is published by renaming a fresh file over the artifact, so
      // an owner-only transcript must not come back at the umask default.
      expect(statSync(transcriptFile).mode & 0o777).toBe(0o600);
    });
  });
});
