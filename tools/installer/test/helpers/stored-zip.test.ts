/**
 * `writeStoredZip` writes the bytes off-Windows hosts hand to the installer, so
 * what it produces has to be a zip by a reader's standard rather than by its
 * own. Everything below is checked with `unzip` — a reader this repo did not
 * write — because a zip validated by the code that wrote it proves only that
 * the two agree.
 *
 * `Expand-Archive` would be the closer mirror of what `install.ps1` does, and
 * it is deliberately NOT used: it is a PowerShell module autoload, which is the
 * exact call this file exists to keep off non-Windows CI (see stored-zip.ts).
 * Reaching for it here would put the flake back inside the test that proves the
 * flake was removed. On Windows the writer is never the one building the
 * archive, so `Expand-Archive`'s real agreement with it is not a thing that has
 * to hold.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { writeStoredZip } from './stored-zip.ts';

/** `unzip`, or undefined where the host has none — Windows, most often. */
function unzipExe(): string | undefined {
  try {
    execFileSync('unzip', ['-v'], { stdio: 'pipe' });
    return 'unzip';
  } catch {
    return undefined;
  }
}

const UNZIP = unzipExe();
const ROOT_NAME = 'aka-win32-x64';

describe('writeStoredZip', () => {
  let dir: string;
  /** A staged `aka-win32-x64/` tree, the shape `writeArchive` hands over. */
  let stage: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-stored-zip-'));
    stage = join(dir, 'stage');
    mkdirSync(join(stage, ROOT_NAME, 'nested'), { recursive: true });
    writeFileSync(join(stage, ROOT_NAME, 'payload.txt'), 'the banner line\n');
    writeFileSync(join(stage, ROOT_NAME, 'aka.exe'), 'not a PE — inert fixture payload\n');
    writeFileSync(join(stage, ROOT_NAME, 'nested', 'deep.txt'), 'a nested file\n');
  });
  afterAll(() => {
    removeTree(dir);
  });

  const write = (name: string): string => {
    const at = join(dir, name);
    writeStoredZip(at, stage, ROOT_NAME);
    return at;
  };

  it('starts with a local file header, so a reader recognises it at all', () => {
    // The floor `assertZipWritten` checks of the PowerShell path, checked of
    // this one too — an empty zip is an EOCD alone (504b0506) and fails here.
    expect(readFileSync(write('magic.zip')).subarray(0, 4).toString('hex')).toBe('504b0304');
  });

  it.skipIf(UNZIP === undefined)('passes a third-party integrity check', () => {
    // `unzip -t` reads every entry and verifies its CRC against the stored one.
    // A wrong length field, a wrong offset or a miscomputed CRC all surface
    // here, and none of them would be visible in the magic number above.
    const out = execFileSync('unzip', ['-t', write('integrity.zip')], { encoding: 'utf8' });
    expect(out).toContain('No errors detected');
  });

  it.skipIf(UNZIP === undefined)('round-trips the tree, rooted at aka-<triple>/', () => {
    // The root is what build-binaries.yml asserts of a real archive and what
    // install.ps1 joins onto to find the binary, so it is pinned as a PATH and
    // not merely as "some entries came back".
    const into = join(dir, 'extracted');
    execFileSync('unzip', ['-q', write('roundtrip.zip'), '-d', into], { stdio: 'pipe' });
    expect(readFileSync(join(into, ROOT_NAME, 'payload.txt'), 'utf8')).toBe('the banner line\n');
    expect(readFileSync(join(into, ROOT_NAME, 'nested', 'deep.txt'), 'utf8')).toBe(
      'a nested file\n',
    );
  });

  it('stamps the fixed 1980 date rather than the wall clock', () => {
    // Read out of the first local header, NOT inferred from two archives
    // matching. That was the original shape of this case and it could not fail:
    // a DOS time field has two-SECOND resolution, so two writes milliseconds
    // apart land in the same tick whether the stamp is fixed or a wall clock,
    // and the equality held either way. Worse, a wall-clock stamp would then be
    // FLAKY rather than failing — red only on the ~0.4% of runs that straddle a
    // tick boundary, which is the shape that gets re-run instead of read.
    const zip = readFileSync(write('stamp.zip'));
    expect(zip.readUInt16LE(10)).toBe(0); // time: 00:00:00
    expect(zip.readUInt16LE(12)).toBe((1 << 5) | 1); // date: 1980-01-01
  });

  it('does not depend on the order the host lists the tree in', () => {
    // The sort in `collect` is a determinism claim, and the host's own readdir
    // order is usually sorted already — so observing one archive proves
    // nothing. Driving a second one through a deliberately reversed listing
    // does: with the sort, both orders yield the same bytes; without it, they
    // cannot.
    const forward = readFileSync(write('order-default.zip'));
    const at = join(dir, 'order-reversed.zip');
    writeStoredZip(at, stage, ROOT_NAME, (d) => readdirSync(d).sort().reverse());
    expect(readFileSync(at).equals(forward)).toBe(true);
  });

  it('writes the same bytes for the same tree, and different bytes for different content', () => {
    // The tampering case rebuilds one archive under one name and asserts the
    // installer refuses the second copy, which rests entirely on the CONTENT
    // moving the bytes. This is the difference half of that; the stability half
    // it used to carry is the case above, which can actually fail.
    const first = readFileSync(write('stable-a.zip'));
    expect(readFileSync(write('stable-b.zip')).equals(first)).toBe(true);

    writeFileSync(join(stage, ROOT_NAME, 'payload.txt'), 'a different banner\n');
    expect(readFileSync(write('changed.zip')).equals(first)).toBe(false);
    writeFileSync(join(stage, ROOT_NAME, 'payload.txt'), 'the banner line\n');
  });
});
