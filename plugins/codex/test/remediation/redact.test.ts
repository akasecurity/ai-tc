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
// scan does not flag this test file (mirrors history/scan.test.ts). Their exact
// value is irrelevant to redaction — the module strikes a verbatim occurrence —
// only that they are distinct and long enough to be a meaningful match.
const ROLLOUT_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const TEMP_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');
const PROJECT_KEY = ['AKIA', 'Z9YXWVUT5SRQPONM'].join('');

describe('redactLeakedKeys', () => {
  // Two in-scope artifact roots (rollout + temp) and one out-of-scope project
  // root, all distinct siblings under the OS temp dir — so the project root shares
  // no ancestry with an artifact root and the scope limit is a structural, not a
  // coincidental, boundary.
  let rolloutRoot: string;
  let tempRoot: string;
  let projectRoot: string;
  let scope: RedactionScope;

  beforeEach(() => {
    rolloutRoot = mkdtempSync(join(tmpdir(), 'aka-redact-rollouts-'));
    tempRoot = mkdtempSync(join(tmpdir(), 'aka-redact-temp-'));
    projectRoot = mkdtempSync(join(tmpdir(), 'aka-redact-project-'));
    scope = { artifactRoots: [rolloutRoot, tempRoot] };
  });

  afterEach(() => {
    rmSync(rolloutRoot, { recursive: true, force: true });
    rmSync(tempRoot, { recursive: true, force: true });
    rmSync(projectRoot, { recursive: true, force: true });
  });

  it('redacts leaked keys in rollout and temp artifacts, returning the real count', () => {
    // A rollout artifact nested under the rollout root, in the year/month/day
    // sharding Codex uses (sessions/YYYY/MM/DD/rollout-*.jsonl).
    const dayDir = join(rolloutRoot, '2026', '07', '01');
    mkdirSync(dayDir, { recursive: true });
    const rolloutFile = join(dayDir, 'rollout-2026-07-01T10-00-00-abc123.jsonl');
    writeFileSync(rolloutFile, `{"content":"here is a key ${ROLLOUT_KEY} in a prompt"}`);

    // A temp artifact directly under the temp root.
    const tempFile = join(tempRoot, 'agent-scratch.txt');
    writeFileSync(tempFile, `scratch buffer ${TEMP_KEY} end`);

    const count = redactLeakedKeys(
      [
        { where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY },
        { where: { filePath: tempFile }, rawValue: TEMP_KEY },
      ],
      scope,
    );

    expect(count).toBe(2);

    // The leaked keys are no longer readable in either artifact.
    const rolloutAfter = readFileSync(rolloutFile, 'utf8');
    expect(rolloutAfter).not.toContain(ROLLOUT_KEY);
    expect(rolloutAfter).toContain('[REDACTED:SECRET]');

    const tempAfter = readFileSync(tempFile, 'utf8');
    expect(tempAfter).not.toContain(TEMP_KEY);
    expect(tempAfter).toContain('[REDACTED:SECRET]');
  });

  it('leaves ordinary project files byte-identical — the binding scope limit', () => {
    const rolloutFile = join(rolloutRoot, 'rollout-session.jsonl');
    writeFileSync(rolloutFile, `leaked ${ROLLOUT_KEY}`);

    // A finding references an ordinary project file too. It must never be touched:
    // in-place redaction of arbitrary project files is out of scope for this flow.
    const projectFile = join(projectRoot, 'config.env');
    writeFileSync(projectFile, `AWS_ACCESS_KEY_ID=${PROJECT_KEY}\n`);
    const projectBytesBefore = readFileSync(projectFile);

    const count = redactLeakedKeys(
      [
        { where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY },
        { where: { filePath: projectFile }, rawValue: PROJECT_KEY },
      ],
      scope,
    );

    // Only the rollout key was redacted; the project-file key is out of scope.
    expect(count).toBe(1);

    // The rollout artifact was redacted.
    expect(readFileSync(rolloutFile, 'utf8')).not.toContain(ROLLOUT_KEY);

    // The project file is byte-for-byte unchanged, key intact.
    expect(readFileSync(projectFile)).toEqual(projectBytesBefore);
    expect(readFileSync(projectFile, 'utf8')).toContain(PROJECT_KEY);
  });

  it('never writes outside the rollout/temp artifact set even for a full project batch', () => {
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
    const multi = join(rolloutRoot, 'rollout-multi.jsonl');
    writeFileSync(multi, `first ${ROLLOUT_KEY} middle ${ROLLOUT_KEY} last`);
    const absent = join(rolloutRoot, 'rollout-absent.jsonl');
    writeFileSync(absent, 'no secret in this rollout');

    const count = redactLeakedKeys(
      [
        { where: { filePath: multi }, rawValue: ROLLOUT_KEY },
        // In scope, but the referenced key is not present in the file.
        { where: { filePath: absent }, rawValue: TEMP_KEY },
      ],
      scope,
    );

    // The absent key was never actually redacted, so it is not counted.
    expect(count).toBe(1);

    const multiAfter = readFileSync(multi, 'utf8');
    expect(multiAfter).not.toContain(ROLLOUT_KEY);
    // BOTH occurrences were struck.
    expect(multiAfter.match(/\[REDACTED:SECRET\]/g)).toHaveLength(2);

    // The file whose key was absent is untouched.
    expect(readFileSync(absent, 'utf8')).toBe('no secret in this rollout');
  });

  it('counts every finding on a repeated value struck, not just the first', () => {
    // The same raw secret value appears twice in one rollout and is surfaced
    // as TWO findings (two targets sharing one rawValue). The first strike's
    // replaceAll clears every occurrence, so the second target's value is already
    // gone — it must still count as struck, never misreported as still exposed.
    const rolloutFile = join(rolloutRoot, 'rollout-repeated.jsonl');
    writeFileSync(rolloutFile, `one ${ROLLOUT_KEY} two ${ROLLOUT_KEY} done`);

    const targets = [
      { where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY },
      { where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY },
    ];
    const detail = redactLeakedKeysDetailed(targets, scope);

    // Both findings resolve on the single rewrite: counted and struck, so a
    // caller diffing its input against `struck` finds nothing left unredacted.
    expect(detail.redactedKeys).toBe(2);
    expect(detail.struck).toEqual(targets);
    expect(readFileSync(rolloutFile, 'utf8')).not.toContain(ROLLOUT_KEY);
  });

  it('the production default scope does not treat an arbitrary temp file as in-scope', () => {
    // Under the real platform default scope (rollouts dir only), a leaked key in
    // a file that merely lives under the OS temp dir is NOT redacted — proving the
    // shipped default never grants redaction over the whole OS temp tree.
    const strayFile = join(tempRoot, 'stray-under-tmp.txt');
    writeFileSync(strayFile, `stray ${TEMP_KEY} value`);
    const bytesBefore = readFileSync(strayFile);

    const count = redactLeakedKeys([{ where: { filePath: strayFile }, rawValue: TEMP_KEY }]);

    expect(count).toBe(0);
    expect(readFileSync(strayFile)).toEqual(bytesBefore);
    expect(readFileSync(strayFile, 'utf8')).toContain(TEMP_KEY);
    // Sanity: the default scope is rollouts-only, not the OS temp dir.
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
    const symlinkInRoot = join(rolloutRoot, 'rollout-escape.jsonl');
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
    const present = join(rolloutRoot, 'rollout-present.jsonl');
    writeFileSync(present, `leaked ${ROLLOUT_KEY} here`);
    const missing = join(tempRoot, 'never-written.txt');

    const count = redactLeakedKeys(
      [
        // The missing target is listed first, so a batch-aborting throw would leave
        // the present artifact un-redacted.
        { where: { filePath: missing }, rawValue: TEMP_KEY },
        { where: { filePath: present }, rawValue: ROLLOUT_KEY },
      ],
      scope,
    );

    // The missing artifact contributes nothing; the present one is still redacted.
    expect(count).toBe(1);
    expect(readFileSync(present, 'utf8')).not.toContain(ROLLOUT_KEY);
    expect(readFileSync(present, 'utf8')).toContain('[REDACTED:SECRET]');
  });

  describe('.aka-redact.tmp cleanup', () => {
    // Entries left behind matching the atomic-write sibling-temp-file naming.
    function orphanedTmpEntries(dir: string): string[] {
      return readdirSync(dir).filter((entry) => entry.endsWith('.aka-redact.tmp'));
    }

    it('leaves no .aka-redact.tmp sibling after a successful redaction', () => {
      const rolloutFile = join(rolloutRoot, 'rollout-session.jsonl');
      writeFileSync(rolloutFile, `leaked ${ROLLOUT_KEY} here`);

      const count = redactLeakedKeys(
        [{ where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY }],
        scope,
      );

      expect(count).toBe(1);
      expect(readFileSync(rolloutFile, 'utf8')).toContain('[REDACTED:SECRET]');
      // The rename consumed the temp file — no orphan sibling remains.
      expect(orphanedTmpEntries(rolloutRoot)).toEqual([]);
    });

    it('leaves no .aka-redact.tmp orphan and the original intact when the atomic write fails', () => {
      const rolloutFile = join(rolloutRoot, 'rollout-session.jsonl');
      const originalContent = `leaked ${ROLLOUT_KEY} here`;
      writeFileSync(rolloutFile, originalContent);

      // Pre-create a DIRECTORY at the exact sibling temp path the atomic write
      // uses. The sweep leaves it (a directory is not something this module
      // wrote) and the exclusive create then refuses to publish through it — a
      // deterministic, OS-level way to force the write/rename step to fail
      // without touching the original file at all.
      const tmpPath = `${rolloutFile}.${String(process.pid)}.aka-redact.tmp`;
      mkdirSync(tmpPath);

      const count = redactLeakedKeys(
        [{ where: { filePath: rolloutFile }, rawValue: ROLLOUT_KEY }],
        scope,
      );

      // The write failed, so nothing was redacted or counted.
      expect(count).toBe(0);
      // The cleanup catch removed the tmp entry — even though it turned out to be
      // a directory rather than a partially written file — so no orphan survives.
      expect(orphanedTmpEntries(rolloutRoot)).toEqual([]);
      // The atomic-write guarantee: the original artifact is untouched.
      expect(readFileSync(rolloutFile, 'utf8')).toBe(originalContent);
    });

    // A pid no platform can hand out: Linux caps `pid_max` at 2^22 and macOS at
    // 99999, so `kill(pid, 0)` answers ESRCH here rather than racing some real
    // process. That makes "a killed earlier run" a fixture rather than a gamble
    // on pid reuse.
    const DEAD_PID = 1_073_741_823;

    // The temp path this module mints for `artifact` when it runs as `pid`.
    function tempName(artifact: string, pid: number): string {
      return `${artifact}.${String(pid)}.aka-redact.tmp`;
    }

    it('sweeps the copy a killed earlier run stranded beside the artifact', () => {
      const file = join(rolloutRoot, 'stranded.jsonl');
      writeFileSync(file, `leaked ${ROLLOUT_KEY} here`);
      // A temp a run that died between the write and the rename left behind: a
      // whole copy of the transcript — every secret it held — that nothing else
      // would ever remove.
      const stranded = tempName(file, DEAD_PID);
      writeFileSync(stranded, `stranded copy ${ROLLOUT_KEY} here`);

      const count = redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      expect(count).toBe(1);
      expect(existsSync(stranded)).toBe(false);
    });

    it('sweeps a stranded copy even when this pass strikes nothing', () => {
      const file = join(rolloutRoot, 'nostrike.jsonl');
      const original = 'nothing leaked here';
      writeFileSync(file, original);
      const stranded = tempName(file, DEAD_PID);
      writeFileSync(stranded, `stranded copy ${ROLLOUT_KEY} here`);

      const count = redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      // The artifact stays byte-identical — the sweep runs on every artifact the
      // pass opens, not only the ones it goes on to rewrite.
      expect(count).toBe(0);
      expect(readFileSync(file, 'utf8')).toBe(original);
      expect(existsSync(stranded)).toBe(false);
    });

    it("leaves a live run's temp file alone", () => {
      const file = join(rolloutRoot, 'live.jsonl');
      writeFileSync(file, `leaked ${ROLLOUT_KEY} here`);
      // The parent of this test process is alive by construction, so its temp is
      // work in progress rather than a leftover — sweeping it would delete
      // another run's bytes out from under its own rename.
      const live = tempName(file, process.ppid);
      writeFileSync(live, 'in flight');

      redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      expect(readFileSync(live, 'utf8')).toBe('in flight');
    });

    it('refuses to publish through a symlink planted at its temp path', (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
      }
      const file = join(rolloutRoot, 'symlink.jsonl');
      const original = `leaked ${ROLLOUT_KEY} here`;
      writeFileSync(file, original);
      // A file outside every artifact root, standing in for whatever a planted
      // link would aim at. Following the link would copy this artifact's whole
      // contents over it and then rename the link itself over the artifact.
      const outside = join(projectRoot, 'notes.txt');
      writeFileSync(outside, 'untouched');
      symlinkSync(outside, tempName(file, process.pid));

      const count = redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      // Doubt at the temp path comes out as "did nothing": no write, no count.
      // The sweep leaves the link (not a regular file, so not ours to remove)
      // and the exclusive create then refuses to publish through it.
      expect(count).toBe(0);
      expect(readFileSync(outside, 'utf8')).toBe('untouched');
      expect(readFileSync(file, 'utf8')).toBe(original);
      expect(lstatSync(file).isSymbolicLink()).toBe(false);
    });

    it('publishes the redacted artifact with the permission bits it had', (ctx) => {
      if (process.platform === 'win32') ctx.skip('POSIX permission bits');
      const file = join(rolloutRoot, 'mode.jsonl');
      writeFileSync(file, `leaked ${ROLLOUT_KEY} here`);
      chmodSync(file, 0o600);

      redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      // The rewrite is published by renaming a fresh file over the artifact, so
      // an owner-only transcript must not come back at the umask default. The
      // remediation that exists BECAUSE the file held a secret must not make it
      // more readable than it was.
      expect(statSync(file).mode & 0o777).toBe(0o600);
    });

    it('clears a leftover carrying its own pid rather than writing through it', (ctx) => {
      if (process.platform === 'win32') ctx.skip('POSIX permission bits');
      const file = join(rolloutRoot, 'leftover.jsonl');
      writeFileSync(file, `leaked ${ROLLOUT_KEY} here`, { mode: 0o600 });
      // The one temp path this process would pick, left behind by an earlier
      // process that happened to carry the same pid. Writing through it would
      // publish the artifact with the leftover's permission bits, since a write
      // applies its mode only when it CREATES the file.
      writeFileSync(tempName(file, process.pid), 'stale', { mode: 0o644 });

      const count = redactLeakedKeys([{ where: { filePath: file }, rawValue: ROLLOUT_KEY }], scope);

      expect(count).toBe(1);
      expect(readFileSync(file, 'utf8')).toContain('[REDACTED:SECRET]');
      expect(statSync(file).mode & 0o777).toBe(0o600);
    });
  });
});
