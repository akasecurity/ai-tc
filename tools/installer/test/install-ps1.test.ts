// The Windows half of the installer trust chain, driven end to end.
//
// The sibling suite's reasoning applies unchanged: install.ps1 is what an
// `irm … | iex` user runs, and nothing in the tree executed it. What differs is
// where each case can run.
//
//   - The two REFUSAL cases exit at step 4, before anything Windows-only, so
//     they run under any PowerShell — including `pwsh` on a developer machine or
//     in a container. That is what makes them mutation-testable off Windows.
//   - The HAPPY PATH needs Windows, and the reason is sharper than "it uses
//     Windows-only APIs". Measured on PowerShell 7.4.6 / Debian 12:
//     `New-Item -ItemType Junction` REPORTS SUCCESS AND CREATES NOTHING —
//     `Test-Path` on the new path is False immediately afterwards and the parent
//     directory is empty. It does not throw, so install.ps1 runs on, prints "is
//     on your PATH", and only fails two lines later on the exec.
//     So a Linux run of this path is not a weaker version of the Windows one; it
//     is a different script, silently missing the step that puts `aka` on PATH.
//     Un-gating it here would assert a behaviour Windows does not have.
//
// ONE CAVEAT, because the happy path has a real side effect and there is no
// override for it. install.ps1 rewrites HKCU's `Path` — that is the feature — so
// this suite snapshots it and puts it back in a `finally`. The restore is exact
// for the entries themselves (the install dir is a temp dir, so nothing real is
// dropped), but it cannot undo one thing: reading and rewriting the value
// through [Environment] expands any `%VAR%` reference and stores the result as a
// plain string. That is what the shipped script does to every user who installs,
// not something this suite introduces — but it is why the happy path is worth
// knowing about before running this package's tests on a Windows workstation.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  archiveNameFor,
  expectedVersionOutput,
  findRealArchive,
  FIXTURE_VERSION,
  hostTriple,
  sha256OfFile,
  writeArchive,
  writeRelease,
  writeSums,
} from './helpers/release-fixture.ts';
import {
  powershellExe,
  readUserPath,
  realDistDir,
  runInstallPs1,
  writeUserPath,
} from './helpers/run-installer.ts';
import { type ReleaseServer, serveRelease } from './helpers/serve-release.ts';

const PS = powershellExe();
const REAL_DIST = realDistDir();
const IS_WIN = process.platform === 'win32';
// The triple install.ps1 derives. Off Windows the harness reports AMD64 so the
// script reaches step 4 at all, so the asset it asks for is still the win32 one.
const TRIPLE = 'win32-x64';

// PowerShell wraps a long error record across lines when its output is
// redirected, which can split a phrase this suite matches on. Flattening
// whitespace reads the message the script wrote rather than the width the host
// chose to print it at.
const flat = (text: string) => text.replace(/\s+/gu, ' ');

// Skipped rather than returned early, so a host with no PowerShell reports these
// as unrun instead of green.
describe.skipIf(PS === undefined)('install.ps1', () => {
  const exe = PS ?? '';
  let root: string;
  let base: string;
  let installDir: string;
  let server: ReleaseServer | undefined;
  let userPathBefore: string | null = null;

  beforeEach(async () => {
    root = mkdtempSync(join(tmpdir(), 'aka-install-ps1-'));
    base = join(root, 'release');
    installDir = join(root, 'local-appdata', 'aka');
    mkdirSync(base, { recursive: true });
    server = await serveRelease(base);
    userPathBefore = IS_WIN ? readUserPath(exe) : null;
  });

  afterEach(async () => {
    // Guarded, and the cleanup is in a `finally`. A beforeEach that threw
    // leaves `server` either unset (first test) or pointing at the PREVIOUS
    // test's closed server, whose close() rejects — either way the real setup
    // error would be masked by a teardown error and the temp tree would leak.
    try {
      await server?.close();
    } finally {
      server = undefined;
      if (IS_WIN) writeUserPath(exe, userPathBefore);
      removeTree(root);
    }
  });

  // `server` is optional so teardown can be guarded; inside a test body
  // beforeEach has run, and a missing one is a harness bug worth naming
  // rather than a `undefined` reaching the child as a URL.
  const serverBase = () => {
    if (server === undefined) throw new Error('the fixture release server was not started');
    return server.base;
  };

  const run = async (version = FIXTURE_VERSION) =>
    await runInstallPs1(exe, { base: serverBase(), version, installDir });

  it.skipIf(!IS_WIN)('downloads, verifies, extracts and links a good release', async () => {
    writeRelease(base, { banner: FIXTURE_VERSION, triple: TRIPLE });

    const result = await run();

    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    // The script runs `aka.exe --version` itself and prints what it got, so this
    // asserts the extracted binary was reached and ran.
    expect(result.stdout).toContain(expectedVersionOutput(FIXTURE_VERSION));

    // Linked onto PATH: the stable `current` junction exists, runs, and is the
    // entry the persisted user Path now leads with.
    const current = join(installDir, 'current');
    expect(existsSync(current)).toBe(true);
    const viaJunction = spawnSync(join(current, 'aka.exe'), ['--version'], { encoding: 'utf8' });
    expect(viaJunction.status).toBe(0);
    expect(viaJunction.stdout.trim()).toBe(expectedVersionOutput(FIXTURE_VERSION));
    expect((readUserPath(exe) ?? '').split(';')).toContain(current);
  });

  it('refuses a tampered archive, and installs nothing', async () => {
    // A complete, correct release…
    writeRelease(base, { banner: FIXTURE_VERSION, triple: TRIPLE });
    // …whose archive is then replaced with a valid one carrying different
    // contents, under the same name, after SHA256SUMS was written. The archive
    // still extracts, so an installer that skipped verification would SUCCEED
    // rather than fail on a corrupt file.
    writeArchive(base, { version: FIXTURE_VERSION, triple: TRIPLE, banner: 'tampered-payload' });

    const result = await run();

    expect(result.status).not.toBe(0);
    expect(flat(result.stderr)).toContain('checksum mismatch');
    // Nothing extracted, nothing linked. The happy path above is the positive
    // control for these reads — without it, a script that always refused would
    // satisfy them.
    expect(existsSync(installDir)).toBe(false);
    if (IS_WIN) expect(readUserPath(exe)).toBe(userPathBefore);
  });

  it('refuses an archive that SHA256SUMS does not list, by the not-listed path', async () => {
    const archivePath = writeArchive(base, {
      version: FIXTURE_VERSION,
      triple: TRIPLE,
      banner: FIXTURE_VERSION,
    });
    // A well-formed SHA256SUMS carrying a correct line for a DIFFERENT asset.
    writeSums(base, [
      { name: archiveNameFor(FIXTURE_VERSION, 'win32-arm64'), sha: sha256OfFile(archivePath) },
    ]);

    const result = await run();

    expect(result.status).not.toBe(0);
    expect(flat(result.stderr)).toContain('not listed in SHA256SUMS');
    // The DISTINCT path, not the mismatch one. Without the `if (-not $line)`
    // guard the unlisted archive is compared against an empty expectation and
    // refused as a mismatch instead — still non-zero, still "refused", and wrong
    // about why. This line is the only thing that separates the two.
    expect(flat(result.stderr)).not.toContain('checksum mismatch');
    expect(existsSync(installDir)).toBe(false);
    if (IS_WIN) expect(readUserPath(exe)).toBe(userPathBefore);
  });

  // Skipped unless a real `archive:sea` output is pointed at; see the sibling
  // suite. build-binaries.yml sets AKA_INSTALLER_REAL_DIST on the Windows target
  // too, so the shipped script installs the zip a user downloads.
  it.skipIf(REAL_DIST === undefined || !IS_WIN)('installs a real release archive', async () => {
    const dist = REAL_DIST ?? '';
    const real = findRealArchive(dist, hostTriple());
    expect(real, `no aka-*-${hostTriple()} archive in ${dist}`).toBeDefined();
    if (real === undefined) return;

    copyFileSync(real.path, join(base, real.name));
    writeSums(base, [{ name: real.name, sha: sha256OfFile(real.path) }]);

    const result = await run(real.version);

    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    // `aka --version` prints a bare X.Y.Z, and it has to be the version the
    // asset name claimed — the installer resolved the asset from that string.
    expect(result.stdout).toContain(real.version);
    const viaJunction = spawnSync(join(installDir, 'current', 'aka.exe'), ['--version'], {
      encoding: 'utf8',
    });
    expect(viaJunction.stdout.trim()).toBe(real.version);
  });
});
