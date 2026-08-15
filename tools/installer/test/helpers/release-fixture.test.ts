// The fixture's own coverage, and it exists for one defect in particular.
//
// The asset NAME follows the triple — `archive-sea.mjs` emits `.zip` for win32
// and `.tar.gz` for everything else, so `archiveNameFor` must too. The FORMAT
// therefore has to follow the triple as well, and the obvious way to write it
// (branch on `process.platform`) silently decouples the two: run the ps1 suite
// anywhere but Windows and the fixture writes a gzipped tarball called `.zip`.
//
// Nothing downstream would have gone red. Both ps1 refusal cases exit at step 4,
// before the extract, so a fixture that is not really a zip is never opened —
// and the one case that would open it is Windows-only, where the bug does not
// occur. It would simply have stopped being a zip, in the suite whose whole job
// is to be honest about what the installer is handed.
import { closeSync, mkdtempSync, openSync, readSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { archiveNameFor, FIXTURE_VERSION, sha256OfFile, writeArchive } from './release-fixture.ts';
import { powershellExe } from './run-installer.ts';

const PS = powershellExe();

/** The first four bytes of a file, as lowercase hex. */
function magicOf(path: string): string {
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(4);
    readSync(fd, buf, 0, 4, 0);
    return buf.toString('hex');
  } finally {
    closeSync(fd);
  }
}

const GZIP = '1f8b';
const ZIP = '504b0304';

describe('the release fixture', () => {
  // In a hook, not the describe body: work in the body runs at COLLECTION time,
  // so a `skipIf` added here later would still create the directory while
  // `afterAll` no longer ran to remove it.
  let root: string;
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-fixture-self-'));
  });
  afterAll(() => {
    removeTree(root);
  });

  it('names an asset the way archive-sea.mjs does', () => {
    expect(archiveNameFor('1.2.3', 'linux-x64')).toBe('aka-1.2.3-linux-x64.tar.gz');
    expect(archiveNameFor('1.2.3', 'win32-x64')).toBe('aka-1.2.3-win32-x64.zip');
  });

  it('writes a real gzip tarball for a posix triple', () => {
    const path = writeArchive(root, {
      version: FIXTURE_VERSION,
      triple: 'linux-x64',
      banner: FIXTURE_VERSION,
    });
    expect(basename(path)).toMatch(/\.tar\.gz$/u);
    expect(magicOf(path).startsWith(GZIP)).toBe(true);
  });

  // Skipped only where no PowerShell exists, since Compress-Archive is what
  // writes a zip. Both hosted Linux and macOS runners ship `pwsh`, so this runs
  // on all three CI legs rather than only the Windows one — which is the whole
  // point: the platform that gets this wrong is the platform that is NOT
  // Windows.
  it.skipIf(PS === undefined)('writes a real zip for a win32 triple on any host', () => {
    const path = writeArchive(root, {
      version: FIXTURE_VERSION,
      triple: 'win32-x64',
      banner: FIXTURE_VERSION,
    });
    expect(basename(path)).toMatch(/\.zip$/u);
    // The assertion the name cannot make. Before the format followed the triple
    // this read `1f8b…` on every non-Windows host.
    expect(magicOf(path)).toBe(ZIP);
  });

  // `runnable` defaults to OFF, and this is what keeps it there. A win32
  // archive that packs the real PE carries a copy of the Node executable —
  // ~115 MB — and building, zipping and expanding that is the most expensive
  // thing this package does. Exactly one case in the suite runs the installed
  // binary and so asks for it; every other archive is refused before the
  // extract and needs nothing startable.
  //
  // Flipping the default back is a one-word edit that no other assertion here
  // would notice, because a runnable archive is CORRECT — just enormous. Only
  // wall-clock would move, and this repo deliberately gates on no wall clock.
  // So the pin is a SIZE, which is deterministic and does not flake: an inert
  // archive is a few hundred bytes and the bound is four orders of magnitude
  // above it, so it can only ever be tripped by a real PE landing in there.
  //
  // One-sided on purpose — it never builds a runnable archive to compare
  // against, since paying the 115 MB once to prove the fixture avoids paying
  // it four times is a poor trade. Windows-gated because that is the only host
  // where the runnable branch does anything: everywhere else the placeholder is
  // written whatever the caller asked, so the assertion would pass vacuously.
  it.skipIf(PS === undefined || process.platform !== 'win32')(
    'leaves the real PE out of a win32 archive unless the caller asks to run it',
    () => {
      const path = writeArchive(root, {
        version: FIXTURE_VERSION,
        triple: 'win32-x64',
        banner: 'inert-payload',
      });
      expect(magicOf(path)).toBe(ZIP);
      expect(statSync(path).size).toBeLessThan(1_000_000);
    },
  );

  it('rewrites the same asset with a different hash when the payload changes', () => {
    // Exactly what the tampered case rests on, and worth asserting here rather
    // than inferring from that case passing: ONE asset name, overwritten in
    // place, hashing differently afterwards. If the second call landed on a
    // second path instead, the tampered case would be serving the original
    // archive and refusing nothing.
    const opts = { version: FIXTURE_VERSION, triple: 'linux-arm64' };
    const path = writeArchive(root, { ...opts, banner: 'original-payload' });
    const before = sha256OfFile(path);

    const again = writeArchive(root, { ...opts, banner: 'tampered-payload' });

    expect(again).toBe(path);
    expect(sha256OfFile(again)).not.toBe(before);
    expect(magicOf(again).startsWith(GZIP)).toBe(true);
  });
});
