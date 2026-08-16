// The POSIX half of the installer trust chain, driven end to end.
//
// tools/installer/install.sh is a SHIPPED security control — it is what a
// `curl … | sh` user runs — and until this suite existed nothing in the tree
// executed it. Its verification step was a property of the source as read: a
// refactor that inverted the comparison, or dropped the guard on an archive
// SHA256SUMS does not list, would have merged green.
//
// Every case here runs the real script. Nothing below reimplements a step of it.
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  archiveNameFor,
  expectedVersionOutput,
  findRealArchive,
  FIXTURE_VERSION,
  hostIsUnsupportedByInstallSh,
  hostTriple,
  sha256OfFile,
  writeArchive,
  writeRelease,
  writeSums,
} from './helpers/release-fixture.ts';
import { realDistDir, runInstallSh } from './helpers/run-installer.ts';
import { type ReleaseServer, serveRelease } from './helpers/serve-release.ts';

const REAL_DIST = realDistDir();

// Two hosts reach no useful assertion here, and both are refusals install.sh
// makes ON PURPOSE before it downloads anything — so both are skipped, and
// skipped rather than returned early so the run reports them.
//   - Windows: `uname -s` under Git Bash reports MINGW64_NT, an unsupported OS.
//   - Intel macOS: `darwin-x64` is refused outright (Apple Silicon only), so
//     every case below would fail on its own message assertions rather than on
//     anything the installer got wrong. Hosted runners are arm64; this fires on
//     a developer machine.
describe.skipIf(process.platform === 'win32' || hostIsUnsupportedByInstallSh())(
  'install.sh',
  () => {
    let root: string;
    let base: string;
    let installDir: string;
    let binDir: string;
    let server: ReleaseServer | undefined;

    beforeEach(async () => {
      root = mkdtempSync(join(tmpdir(), 'aka-install-sh-'));
      base = join(root, 'release');
      // Neither of these is created here. Both installers make their own, so
      // "does it exist" is a clean read of whether the script got that far.
      installDir = join(root, 'share');
      binDir = join(root, 'bin');
      mkdirSync(base);
      server = await serveRelease(base);
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
      await runInstallSh({ base: serverBase(), version, installDir, binDir });

    it('downloads, verifies, extracts and links a good release', async () => {
      writeRelease(base, { banner: FIXTURE_VERSION });

      const result = await run();

      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
      // The script runs `aka --version` itself and prints what it got, so this
      // asserts the extracted binary was reached and ran.
      expect(result.stdout).toContain(expectedVersionOutput(FIXTURE_VERSION));

      // Linked onto PATH: a symlink, pointing inside the install dir, runnable
      // through the link rather than only at its target.
      const link = join(binDir, 'aka');
      expect(lstatSync(link).isSymbolicLink()).toBe(true);
      expect(realpathSync(link).startsWith(realpathSync(installDir))).toBe(true);
      const viaLink = spawnSync(link, ['--version'], { encoding: 'utf8' });
      expect(viaLink.status).toBe(0);
      expect(viaLink.stdout.trim()).toBe(expectedVersionOutput(FIXTURE_VERSION));
    });

    it('refuses a tampered archive, and installs nothing', async () => {
      // A complete, correct release…
      writeRelease(base, { banner: FIXTURE_VERSION });
      // …whose archive is then replaced with a valid one carrying different
      // contents, under the same name, after SHA256SUMS was written. This is the
      // shape that matters: the archive still extracts, so an installer that
      // skipped verification would SUCCEED rather than fail on a corrupt file,
      // and the exit-code assertion below would pass for the wrong reason.
      writeArchive(base, {
        version: FIXTURE_VERSION,
        triple: hostTriple(),
        banner: 'tampered-payload',
      });

      const result = await run();

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('checksum mismatch');
      // Nothing extracted, nothing linked. The happy path above is the positive
      // control for these two reads — without it, a script that always refused
      // would satisfy them.
      expect(existsSync(installDir)).toBe(false);
      expect(existsSync(binDir)).toBe(false);
    });

    it('refuses an archive that SHA256SUMS does not list, by the not-listed path', async () => {
      const archivePath = writeArchive(base, {
        version: FIXTURE_VERSION,
        triple: hostTriple(),
        banner: FIXTURE_VERSION,
      });
      // A well-formed SHA256SUMS carrying a correct line for a DIFFERENT asset.
      // The archive being downloaded is simply absent from it.
      writeSums(base, [
        { name: archiveNameFor(FIXTURE_VERSION, 'linux-riscv64'), sha: sha256OfFile(archivePath) },
      ]);

      const result = await run();

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain('not listed in SHA256SUMS');
      // The DISTINCT path, not the mismatch one. Without the `[ -n "$want" ]`
      // guard an unlisted archive compares against an empty expectation and is
      // refused as a mismatch instead — still non-zero, still "refused", and
      // wrong about why. This line is the only thing that separates the two.
      expect(result.stderr).not.toContain('checksum mismatch');
      expect(existsSync(installDir)).toBe(false);
      expect(existsSync(binDir)).toBe(false);
    });

    // Skipped unless a real `archive:sea` output is pointed at. build-binaries.yml
    // sets AKA_INSTALLER_REAL_DIST after building the SEA, so on every supported
    // target the shipped script installs the artifact a user downloads — the one
    // link of the chain that had never run outside a human's terminal.
    it.skipIf(REAL_DIST === undefined)('installs a real release archive', async () => {
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
      const viaLink = spawnSync(join(binDir, 'aka'), ['--version'], { encoding: 'utf8' });
      expect(viaLink.stdout.trim()).toBe(real.version);
    });
  },
);
