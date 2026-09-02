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
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  archiveNameFor,
  compressArchive,
  FIXTURE_VERSION,
  sha256OfFile,
  writeArchive,
} from './release-fixture.ts';
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

/**
 * The retry inside `compressArchive`, driven through its injected runner.
 *
 * It exists for an abort that cannot be provoked on demand — `pwsh` dying with a
 * truncated assembly name, on some hosts, for a command that is correct — so
 * against a real PowerShell the retry branch is dead code on every leg that runs
 * this suite. The failure is injected instead: a runner that aborts a bounded
 * number of times then succeeds, one that aborts forever, and one that fails the
 * ordinary way. Between them they pin that it retries the abort, that it gives
 * up rather than looping, and that it does NOT swallow a real failure.
 *
 * `signal` is what each fake sets, because that is what the real one carries: a
 * child killed by a signal reports `status: null, signal: 'SIGABRT'`, while
 * every genuine `Compress-Archive` failure leaves through a non-zero exit.
 */
describe('compressArchive', () => {
  // Its own directory rather than the fixture suite's: nothing here writes a
  // real archive, and sharing one would couple two independent describes.
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-compress-retry-'));
  });
  afterAll(() => {
    removeTree(dir);
  });

  const aborted = (): Error =>
    Object.assign(new Error('Command failed'), { status: null, signal: 'SIGABRT' });
  /** What a successful Compress-Archive leaves: enough of a zip to satisfy the
   *  post-condition. The fakes have to write it, because a runner that returns
   *  without producing an archive is exactly what that check exists to catch. */
  const landZip = (at: string): void => {
    writeFileSync(at, Buffer.from('504b0304', 'hex'));
  };

  const exited = (): Error =>
    Object.assign(new Error('Command failed'), { status: 1, signal: null });

  it('runs the command once when it succeeds', () => {
    // The positive control. Without it every assertion below could be satisfied
    // by an implementation that never calls the runner at all.
    const calls: string[][] = [];
    const at = join(dir, 'control.zip');
    compressArchive('pwsh', '/stage/aka-win32-x64', at, (_exe, args) => {
      calls.push([...args]);
      landZip(at);
    });

    expect(calls).toHaveLength(1);
    // The command is still the one archive-sea.mjs writes, retry or not.
    expect(calls[0]?.at(-1)).toContain('Compress-Archive -Force -CompressionLevel NoCompression');
  });

  it('retries an abort and returns once it lands', () => {
    // Two aborts then success — the shape observed in CI, where one call in a
    // job aborted and another completed. A single-attempt implementation fails
    // this.
    let attempts = 0;
    const at = join(dir, 'flaky.zip');
    compressArchive('pwsh', '/stage/aka-win32-x64', at, () => {
      attempts += 1;
      if (attempts < 3) throw aborted();
      landZip(at);
    });

    expect(attempts).toBe(3);
  });

  it('gives up on an abort that never clears, and rethrows the original', () => {
    // A host where this is not flaking. The budget is spent rather than looped,
    // and what surfaces is the error the caller can act on — not one this retry
    // invented, which would bury the assembly-name detail that identifies it.
    let attempts = 0;
    const original = aborted();

    expect(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', join(dir, 'doomed.zip'), () => {
        attempts += 1;
        throw original;
      });
    }).toThrow(original);

    // Pinned as a COUNT, with no elapsed assertion: a wall-clock bound on a
    // shared runner is the flake this file is trying to remove, not add.
    expect(attempts).toBe(3);
  });

  it('does not retry an ordinary failure', () => {
    // The case that keeps this narrow. A `Compress-Archive` that genuinely
    // cannot write exits non-zero, and must surface on the FIRST attempt — a
    // retry there would turn one clear error into three and still fail.
    let attempts = 0;

    expect(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', join(dir, 'broken.zip'), () => {
        attempts += 1;
        throw exited();
      });
    }).toThrow();

    expect(attempts).toBe(1);
  });

  it('reports that nothing was written when the runner succeeds without producing a file', () => {
    // The post-condition's primary case, per its own docblock: a
    // non-terminating error record leaves pwsh exiting 0 having written
    // nothing. rmSync runs before every attempt, so "wrote nothing" means
    // there is no file to open at all, not a partial one — a bare ENOENT,
    // not the magic-number check below. A carrier with no `.signal` is not
    // the abort, so this must not retry either.
    let attempts = 0;

    expect(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', join(dir, 'empty.zip'), () => {
        attempts += 1;
        // Returns normally without writing anything.
      });
    }).toThrow(/reported success but wrote nothing to/);

    expect(attempts).toBe(1);
  });

  it('keeps the errno when an archive was written but cannot be opened', (ctx) => {
    // The message above is a claim about what PowerShell did, so only the
    // errno that supports it may produce it. A file that IS there and cannot
    // be read — a mode that denies it here, EMFILE under a parallel suite —
    // has to arrive with its own errno intact; reported as "wrote nothing" it
    // sends the reader after a non-terminating error record that never
    // happened, on a file sitting right there with bytes in it.
    const at = join(dir, 'unreadable.zip');
    if (!denyingReadsWorks(join(dir, 'chmod-probe'))) {
      // Root ignores the mode, and Windows has no bit that removes read
      // access. Skipped rather than returned: a pass here would be a claim
      // this run never checked.
      ctx.skip('chmod cannot deny reads on this host');
    }

    let attempts = 0;
    const error = errorFrom(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', at, () => {
        attempts += 1;
        landZip(at);
        chmodSync(at, 0o000);
      });
    });

    // What it SAYS before what it omits — a never-thrown error arrives as
    // undefined, and the assertion below would then read as vacuous.
    expect(error).toBeDefined();
    expect((error as NodeJS.ErrnoException | undefined)?.code).toBe('EACCES');
    expect(error?.message).not.toContain('reported success but wrote nothing');
    // Not the abort either, so it surfaces on the first attempt.
    expect(attempts).toBe(1);
  });

  it('reports a bad magic number when the runner writes a non-zip file', () => {
    // The post-condition's secondary case: a file exists but is not a zip —
    // a partial write, or a non-terminating error record with a different
    // shape. Distinct from the "wrote nothing" case above, and the message
    // says which one happened.
    const at = join(dir, 'garbage.zip');
    let attempts = 0;

    expect(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', at, () => {
        attempts += 1;
        writeFileSync(at, 'not a zip');
      });
    }).toThrow(/is not a zip — read \d+ byte\(s\)/);

    expect(attempts).toBe(1);
  });

  it('refuses an archive with no entries, which is a real zip a reader expects to pass', () => {
    // The one case the docblock's "floor, not a validation" paragraph makes a
    // claim about, pinned rather than left as prose: unlike `not a zip` above,
    // this IS a well-formed zip — `unzip` reads it as empty rather than
    // rejecting it — so a reader reasoning about what still gets past the
    // check would expect it through. It does not get through: an archive with
    // no entries has no local file header, so it starts at the EOCD record and
    // fails on those bytes.
    //
    // Worth an assertion because the paragraph was measurably wrong before and
    // nothing could catch that — prettier is clean either way and no test
    // reads a comment. This is what makes the corrected sentence load-bearing:
    // loosen the magic check to any `504b` and this goes red.
    const at = join(dir, 'no-entries.zip');
    const EOCD_ONLY = Buffer.concat([Buffer.from('504b0506', 'hex'), Buffer.alloc(18)]);

    expect(() => {
      compressArchive('pwsh', '/stage/aka-win32-x64', at, () => {
        writeFileSync(at, EOCD_ONLY);
      });
    }).toThrow(/is not a zip — read 4 byte\(s\), starting 504b0506/);

    // The 22 bytes the paragraph names, so a fixture that stopped being the
    // canonical empty zip cannot keep satisfying the assertion above.
    expect(statSync(at).size).toBe(22);
  });

  it('is what writeArchive uses, so a revert to a bare spawn is caught', () => {
    // Everything above drives `compressArchive` directly. That leaves the one
    // edit which actually changes CI behaviour — the call site inside
    // `writeArchive` — asserted by nothing: revert it to a bare spawn and every
    // other case here stays green. This is the case that goes red.
    //
    // `exe` is injected alongside the runner so this runs everywhere rather than
    // only where a PowerShell exists — the hosts without one are exactly the
    // hosts where the retry branch would otherwise never be executed.
    let attempts = 0;
    const at = join(dir, archiveNameFor(FIXTURE_VERSION, 'win32-x64'));

    const path = writeArchive(
      dir,
      { version: FIXTURE_VERSION, triple: 'win32-x64', banner: FIXTURE_VERSION },
      {
        exe: 'pwsh',
        run: () => {
          attempts += 1;
          if (attempts < 2) throw aborted();
          landZip(at);
        },
      },
    );

    expect(attempts).toBe(2);
    expect(basename(path)).toMatch(/\.zip$/u);
  });

  it('clears a partial archive before each attempt', () => {
    // What stops a retry being worse than the abort. `writeRelease` hashes
    // whatever bytes are on disk into SHA256SUMS, so a truncated archive left by
    // an aborted attempt and carried into the next one would be listed
    // correctly — a self-consistent release that proves nothing. Each attempt
    // therefore starts from no file at all.
    const path = join(dir, 'partial.zip');
    const seen: boolean[] = [];
    let attempts = 0;

    compressArchive('pwsh', '/stage/aka-win32-x64', path, () => {
      attempts += 1;
      seen.push(existsSync(path));
      // Leave a partial behind, exactly as an abort mid-write would.
      writeFileSync(path, 'truncated');
      if (attempts < 2) throw aborted();
      landZip(path);
    });

    expect(seen).toEqual([false, false]);
  });
});

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

  // No longer gated on a PowerShell, and that is a real widening rather than
  // tidying: off Windows the zip is written by stored-zip.ts, so this runs on
  // every host including one with no pwsh at all. The platform that gets a
  // win32 fixture wrong is the platform that is NOT Windows, so the case that
  // catches it should be the one that never skips.
  it('writes a real zip for a win32 triple on any host', () => {
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

/** The error a thunk threw, captured OUTSIDE its own catch. */
function errorFrom(fn: () => void): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}

/**
 * Whether `chmod 0o000` really denies a read on this host, PERFORMED rather
 * than modelled: root ignores the mode, and Windows has no bit that removes
 * read access, so a platform check alone would still be wrong for a rootful
 * container on Linux. The caller skips when this is false, because the case it
 * gates would otherwise drive the readable path and assert nothing.
 */
function denyingReadsWorks(at: string): boolean {
  writeFileSync(at, 'probe');
  chmodSync(at, 0o000);
  try {
    closeSync(openSync(at, 'r'));
    return false;
  } catch {
    return true;
  } finally {
    // Handed back writable before teardown sees it: on Windows `0o000` sets the
    // read-only ATTRIBUTE, which `rmSync` meets as EPERM — tolerated there, so
    // the tree would be left behind silently rather than failing anything.
    chmodSync(at, 0o600);
  }
}
