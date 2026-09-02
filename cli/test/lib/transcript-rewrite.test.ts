import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import type { TransformResult } from '../../src/lib/transcript-rewrite.ts';
import {
  containedRealPath,
  rewriteContainedFile,
  transcriptRoots,
} from '../../src/lib/transcript-rewrite.ts';

// `rewriteContainedFile` puts recovered PLAINTEXT back into a transcript, so
// its temp file is a spill hazard in its own right: bytes that never reach the
// rename still sat on disk in the clear. This suite drives REAL files in a real
// transcript root — the naming, the sweep and the exclusive create are only
// observable against a directory that really holds the neighbours they must and
// must not touch.
//
// The value below is deliberately not secret-shaped: nothing on this path
// scans, and a public tree is no place for a credential-shaped literal.
const RESTORED_RAW = 'quixotic-vellum-marzipan-42';
const POINTER = '[[aka:code_context:AE.QUIXOTICVELLUM.MARZIPAN42]]';

// A pid no platform can hand out: Linux caps `pid_max` at 2^22 and macOS at
// 99999, so `kill(pid, 0)` is ESRCH here rather than a race with some real
// process. That makes "a killed earlier run" a fixture rather than a gamble on
// pid reuse.
const DEAD_PID = 1_073_741_823;

let userHome: string;
let transcript: string;

beforeEach(() => {
  userHome = mkdtempSync(join(tmpdir(), 'aka-cli-rewrite-'));
  mkdirSync(join(userHome, '.claude', 'projects', 'demo'), { recursive: true });
  transcript = join(userHome, '.claude', 'projects', 'demo', 'session.jsonl');
  writeFileSync(transcript, `${JSON.stringify({ text: `path ${POINTER}` })}\n`);
});

afterEach(() => {
  removeTree(userHome);
});

/** The resolved in-root path, exactly as `aka vault prune` hands it over. */
function target(): string {
  const real = containedRealPath(transcript, transcriptRoots(userHome));
  if (real === null) throw new Error('fixture transcript is not inside the transcript root');
  return real;
}

function tempName(realPath: string, pid: number): string {
  return `${realPath}.${String(pid)}.aka-prune.tmp`;
}

/** Every `.aka-prune.tmp` sibling left in the transcript's directory. */
function tempSiblings(): string[] {
  return readdirSync(dirname(target()))
    .filter((name) => name.endsWith('.aka-prune.tmp'))
    .sort();
}

const restore = (text: string): Promise<TransformResult> =>
  Promise.resolve({ text: text.split(POINTER).join(RESTORED_RAW), replaced: 1 });

const refuse = (): Promise<TransformResult> => Promise.resolve({ abort: 'nope' });

describe('rewriteContainedFile', () => {
  it('restores the value and leaves no temp file holding it', async () => {
    const outcome = await rewriteContainedFile(target(), restore);

    expect(outcome).toEqual({ status: 'rewritten', replaced: 1 });
    expect(readFileSync(target(), 'utf8')).toContain(RESTORED_RAW);
    // The plaintext exists in exactly one place afterwards: the transcript.
    expect(tempSiblings()).toEqual([]);
  });

  it('sweeps the plaintext a killed earlier run stranded beside the transcript', async () => {
    const stranded = tempName(target(), DEAD_PID);
    writeFileSync(stranded, `spilled ${RESTORED_RAW}\n`);

    await rewriteContainedFile(target(), restore);

    // Nothing else would ever remove this file, and it holds a recovered value
    // in the clear.
    expect(existsSync(stranded)).toBe(false);
    expect(tempSiblings()).toEqual([]);
  });

  it('sweeps a stranded temp even when this pass then aborts', async () => {
    const stranded = tempName(target(), DEAD_PID);
    writeFileSync(stranded, `spilled ${RESTORED_RAW}\n`);
    const before = readFileSync(target(), 'utf8');

    const outcome = await rewriteContainedFile(target(), refuse);

    // The posture is about the TRANSCRIPT: it stays byte-identical. The spill
    // an earlier run left is still cleared, because the sweep runs before the
    // transform has a say.
    expect(outcome).toEqual({ status: 'aborted', reason: 'nope' });
    expect(readFileSync(target(), 'utf8')).toBe(before);
    expect(existsSync(stranded)).toBe(false);
  });

  it('reuses its own pid without colliding with a leftover of that pid', async () => {
    // The one temp path this process would pick, left behind by an earlier
    // process that happened to carry the same pid. It must be cleared, not
    // written through — writing through would keep the leftover's mode.
    const ours = tempName(target(), process.pid);
    writeFileSync(ours, 'stale', { mode: 0o644 });

    const outcome = await rewriteContainedFile(target(), restore);

    expect(outcome).toEqual({ status: 'rewritten', replaced: 1 });
    expect(readFileSync(target(), 'utf8')).toContain(RESTORED_RAW);
    expect(tempSiblings()).toEqual([]);
  });

  it('leaves a live run temp file alone', async () => {
    // The parent of this test process is alive by construction, so its temp is
    // work in progress rather than a spill — sweeping it would delete another
    // run's bytes out from under its own rename.
    const live = tempName(target(), process.ppid);
    writeFileSync(live, 'in flight');

    await rewriteContainedFile(target(), restore);

    expect(existsSync(live)).toBe(true);
  });

  it('never removes a sibling this module did not name', async () => {
    const real = target();
    const bystanders = [
      // The pid-free shape: nothing this module mints.
      `${real}.aka-prune.tmp`,
      `${real}.notapid.aka-prune.tmp`,
      `${real}. 7.aka-prune.tmp`,
      // A temp belonging to a DIFFERENT transcript in the same directory.
      `${join(dirname(real), 'other.jsonl')}.${String(DEAD_PID)}.aka-prune.tmp`,
      // The suffix has to end the name, not merely appear in it.
      `${tempName(real, DEAD_PID)}.bak`,
    ];
    for (const path of bystanders) writeFileSync(path, 'not ours');

    await rewriteContainedFile(real, restore);

    for (const path of bystanders) expect(existsSync(path)).toBe(true);
  });

  it('aborts, transcript untouched, when a directory occupies the temp path', async () => {
    // A directory is not something this module wrote, so the sweep leaves it —
    // and the exclusive create then refuses to publish through it. Doubt has to
    // come out as "did nothing".
    mkdirSync(tempName(target(), process.pid));
    const before = readFileSync(target(), 'utf8');

    const outcome = await rewriteContainedFile(target(), restore);

    expect(outcome).toEqual({ status: 'aborted', reason: 'the rewrite could not be written' });
    expect(readFileSync(target(), 'utf8')).toBe(before);
  });

  it('publishes the restored transcript with the permission bits it had', async (ctx) => {
    if (process.platform === 'win32') ctx.skip('POSIX permission bits');
    chmodSync(target(), 0o600);

    await rewriteContainedFile(target(), restore);

    // The exclusive create is what binds this: the mode is applied by the
    // create, so plaintext never lands in an inode at the umask default.
    expect(statSync(target()).mode & 0o777).toBe(0o600);
  });
});
