// Builds a throwaway "release" on disk — the archive an installer downloads plus
// the aggregated SHA256SUMS it verifies against — so the real install scripts can
// be driven without a GitHub release or a 46 MB SEA build.
//
// Both shapes are copied from the two links of the chain that already run in CI,
// not invented, because a fixture that got either wrong would make the refusal
// cases pass for the wrong reason:
//   - cli/scripts/archive-sea.mjs emits `aka-<version>-<triple>.(tar.gz|zip)`
//     rooted at `aka-<triple>/`, and writes `<sha>  <name>` into a sidecar
//     `.sha256`.
//   - .github/workflows/release-binaries.yml concatenates those sidecars into one
//     SHA256SUMS.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { powershellEnv, powershellExe } from './run-installer.ts';

/** A version no real release carries, so a fixture can never be mistaken for one. */
export const FIXTURE_VERSION = '0.0.0-fixture';

/**
 * The target triple the install scripts compute for the host they run on.
 * Mirrors install.sh's uname mapping and install.ps1's PROCESSOR_ARCHITECTURE
 * switch — the archive has to be named for the triple the SCRIPT derives, not
 * the one this file would prefer.
 */
export function hostTriple(): string {
  if (process.platform === 'win32') return 'win32-x64';
  return `${process.platform}-${process.arch === 'arm64' ? 'arm64' : 'x64'}`;
}

/**
 * True where install.sh refuses this host before it downloads anything.
 *
 * `darwin-x64` is the case: install.sh carries an explicit Intel-macOS refusal,
 * so on an Intel Mac every case would fail on its own message assertions rather
 * than on anything the installer got wrong. That is a platform the product does
 * not support, not a defect, so the caller skips instead — the same shape as the
 * win32 gate on the suite as a whole. Hosted runners are arm64, so this only
 * ever fires on a developer machine.
 */
export function hostIsUnsupportedByInstallSh(): boolean {
  return hostTriple() === 'darwin-x64';
}

/** The asset filename for a version + triple, per archive-sea.mjs. */
export function archiveNameFor(version: string, triple: string): string {
  return `aka-${version}-${triple}.${triple.startsWith('win32') ? 'zip' : 'tar.gz'}`;
}

/** The hex SHA-256 of a file, the same digest both installers compute. */
export function sha256OfFile(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Write a SHA256SUMS listing exactly these entries, in the two-space format
 * `shasum`/`sha256sum` emit and both installers parse.
 */
export function writeSums(
  intoDir: string,
  entries: readonly { name: string; sha: string }[],
): void {
  writeFileSync(
    join(intoDir, 'SHA256SUMS'),
    entries.map((entry) => `${entry.sha}  ${entry.name}\n`).join(''),
  );
}

/**
 * What the packed stub prints for `--version`.
 *
 * On POSIX the stub is a two-line shell script, so it prints whatever it is
 * given. On Windows the installer runs `aka.exe`, which has to be a real PE —
 * the only one guaranteed present is the Node executable running this suite, so
 * the stub is a copy of it and the version it prints is Node's.
 */
export function expectedVersionOutput(banner: string): string {
  return process.platform === 'win32' ? process.version : `aka ${banner}`;
}

/**
 * Put an `aka.exe` in a win32 fixture root.
 *
 * A genuine PE is copied only when the caller says a case will RUN the binary,
 * and the only one guaranteed present is the Node executable this suite runs
 * under — ~115 MB of it. Copying that, zipping it and expanding it again is the
 * most expensive thing this package does, and it is why the flag defaults to
 * OFF: of the archives the Windows leg builds, exactly one is ever executed.
 *
 * Every other case is refused BEFORE the extract, so all it needs of `aka.exe`
 * is that it exist and move the archive's bytes — not that it start. Those
 * cases assert the install dir was never created, and that assertion keeps its
 * whole discriminating power with an inert payload: `install.ps1` creates the
 * dir and extracts into it (L66-68) well before it runs the binary (L94), and
 * removes only its download temp on the way out, never the install dir. So a
 * verification that got skipped still leaves the dir behind and still fails the
 * case — the control does not rest on the payload being startable.
 *
 * Defaulting the other way would be the quiet failure: a refusal case added
 * later would pay 115 MB and nothing would say so. This way a case that really
 * does need to run the binary gets a loud, immediate refusal to start instead.
 *
 * Off Windows there is no PE to copy and none is needed, so the placeholder is
 * written whatever the caller asked for. It says what it is in its own bytes
 * rather than leaving a reader to wonder why an `.exe` did not start.
 */
function writeWindowsPayload(root: string, banner: string, runnable: boolean): void {
  const exePath = join(root, 'aka.exe');
  if (runnable && process.platform === 'win32') {
    copyFileSync(process.execPath, exePath);
    return;
  }
  writeFileSync(
    exePath,
    `not a PE — inert fixture payload for a win32 archive on ${process.platform} (${banner})\n`,
  );
}

/**
 * Write the archive an installer will download into `intoDir` and return its
 * path. Rooted at `aka-<triple>/`, matching what build-binaries.yml asserts of a
 * real one.
 *
 * Calling this a second time with a different `banner` overwrites the archive
 * with different CONTENTS under the same name — which is what tampering with a
 * release after its SHA256SUMS was written looks like on the wire.
 *
 * `runnable` asks for a win32 payload that will actually START, and costs a
 * ~115 MB copy of the Node executable to provide — pass it only from a case
 * that runs the installed binary, which today is one case in this package. See
 * `writeWindowsPayload` for why the refusal cases lose nothing without it.
 *
 * THE FORMAT FOLLOWS THE TRIPLE, NOT THE HOST, and that is not a detail. The
 * NAME already follows the triple (`archiveNameFor`), so a host-keyed format
 * writes a gzipped tar called `.zip` the moment the ps1 suite runs anywhere but
 * Windows — a fixture that is wrong about the one thing the installer does with
 * it after verifying. The refusal cases never extract, so nothing would have
 * gone red; it would simply have stopped being a zip nobody noticed.
 */
export function writeArchive(
  intoDir: string,
  {
    version,
    triple,
    banner,
    runnable = false,
  }: { version: string; triple: string; banner: string; runnable?: boolean },
): string {
  const archivePath = join(intoDir, archiveNameFor(version, triple));
  const stage = mkdtempSync(join(tmpdir(), 'aka-fixture-stage-'));
  const rootName = `aka-${triple}`;
  const root = join(stage, rootName);
  try {
    mkdirSync(root);
    // Carried whatever the format, so the banner always changes the archive's
    // bytes even where the executable itself cannot.
    writeFileSync(join(root, 'payload.txt'), `${banner}\n`);
    if (triple.startsWith('win32')) {
      writeWindowsPayload(root, banner, runnable);
      // Whatever PowerShell this host has, rather than `powershell` — which is
      // Windows-only, while `Compress-Archive` ships with pwsh everywhere. The
      // ps1 suite skips outright without one, so a caller that got here has one.
      const exe = powershellExe();
      if (exe === undefined) {
        throw new Error(
          `cannot build ${archiveNameFor(version, triple)}: a zip fixture needs a PowerShell ` +
            '(Compress-Archive), and this host has neither `powershell` nor `pwsh`',
        );
      }
      // Mirrors archive-sea.mjs's Compress-Archive, with -CompressionLevel
      // NoCompression added: the installer only hashes the archive and expands
      // it, and neither step cares whether the entries were deflated, so every
      // cycle spent compressing buys the fixture nothing but wall clock. This
      // read `Fastest` first, which reasons the same way but stops one step
      // short — `Fastest` still deflates, and it is deflating the ~115 MB Node
      // binary the runnable archive carries, on the platform with the most
      // expensive fsync of the three. `NoCompression` stores instead, and
      // `Expand-Archive` reads a stored zip exactly the same way.
      execFileSync(
        exe,
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `Compress-Archive -Force -CompressionLevel NoCompression -Path '${root}' -DestinationPath '${archivePath}'`,
        ],
        // The same env every other PowerShell child here gets, rather than a
        // bare inherit. `Compress-Archive` is an autoloaded module, so this
        // child depends on the module path exactly as the script under test
        // does; a bare inherit hands Windows PowerShell whatever PSModulePath
        // the parent had -- pwsh 7's, under Actions' default shell -- which is
        // the one value that costs it its own standard library.
        { stdio: 'pipe', env: powershellEnv() },
      );
    } else {
      const stub = join(root, 'aka');
      writeFileSync(stub, `#!/bin/sh\necho "aka ${banner}"\n`);
      // chmod rather than the writeFileSync mode: a umask only ever CLEARS bits,
      // so a restrictive one would leave the stub non-executable and install.sh
      // would refuse it at the `[ -x ]` check for a reason the fixture invented.
      chmodSync(stub, 0o755);
      execFileSync('tar', ['-czf', archivePath, '-C', stage, rootName], { stdio: 'pipe' });
    }
    return archivePath;
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

/**
 * The real release archive for `triple` in `dir`, or undefined.
 *
 * The version is read back OUT of the filename rather than from a manifest: the
 * installer resolves the asset name from AKA_VERSION, so the two have to agree,
 * and taking both from one string is what makes them.
 */
export function findRealArchive(
  dir: string,
  triple: string,
): { path: string; name: string; version: string } | undefined {
  // Escaped for the reason required-checks.test.js escapes its job key: today's
  // triples carry no metacharacter, and the cost of not depending on that is one
  // call.
  const escaped = triple.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const pattern = new RegExp(`^aka-(.+)-${escaped}\\.(?:tar\\.gz|zip)$`, 'u');
  for (const name of readdirSync(dir)) {
    const version = pattern.exec(name)?.[1];
    if (version !== undefined) return { path: join(dir, name), name, version };
  }
  return undefined;
}

/**
 * Stage a complete, self-consistent release in `intoDir`: one archive plus a
 * SHA256SUMS that lists it correctly. The happy path installs from this; the
 * refusal cases break it afterwards, each in one specific way.
 */
export function writeRelease(
  intoDir: string,
  {
    version = FIXTURE_VERSION,
    triple = hostTriple(),
    banner,
    runnable = false,
  }: { version?: string; triple?: string; banner: string; runnable?: boolean },
): { archivePath: string; archiveName: string; version: string; triple: string } {
  const archivePath = writeArchive(intoDir, { version, triple, banner, runnable });
  const archiveName = archiveNameFor(version, triple);
  writeSums(intoDir, [{ name: archiveName, sha: sha256OfFile(archivePath) }]);
  return { archivePath, archiveName, version, triple };
}
