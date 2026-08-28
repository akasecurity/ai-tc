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
  closeSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
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
 * Bounded deliberately, and short. A host where this fails three times running
 * is not flaking, and turning that into a longer stall would replace a clear
 * error with a slow one.
 */
const COMPRESS_ATTEMPTS = 3;

/** The one signal retried — see the note on the abort below. */
const RETRYABLE_SIGNAL = 'SIGABRT';

/** What `compressArchive` shells out with, injectable so the abort can be driven. */
export type CompressRunner = (exe: string, args: readonly string[]) => void;

const runCompress: CompressRunner = (exe, args) => {
  // The same env every other PowerShell child here gets, rather than a bare
  // inherit. `Compress-Archive` is an autoloaded module, so this child depends
  // on the module path exactly as the script under test does; a bare inherit
  // hands Windows PowerShell whatever PSModulePath the parent had -- pwsh 7's,
  // under Actions' default shell -- which is the one value that costs it its own
  // standard library.
  execFileSync(exe, [...args], { stdio: 'pipe', env: powershellEnv() });
};

/**
 * Prove an attempt actually produced a zip, so the signal fingerprint below is
 * not the only thing standing between a bad archive and SHA256SUMS.
 *
 * `Compress-Archive` does not always report failure through the exit code: a
 * non-terminating error record leaves `pwsh` exiting 0 having written nothing,
 * and no discriminator keyed on status or signal can see that. What consumes
 * this hashes whatever is on disk, so the cheapest honest check is that the
 * bytes are a zip at all.
 *
 * It is a floor, not a validation. An EOCD-only archive — what an empty `-Path`
 * produces — is a structurally valid 22-byte zip and passes this; the guard
 * against that is the staging directory being built immediately above, not
 * anything here.
 */
function assertZipWritten(archivePath: string): void {
  let fd: number;
  try {
    fd = openSync(archivePath, 'r');
  } catch (err) {
    // rmSync ran before this attempt, so "wrote nothing" — the failure this
    // guards against — means there is no file to open at all, not a partial
    // one. That is the more likely of the two non-zip outcomes, so it gets its
    // own message rather than falling through to the magic-number check below,
    // which only ever fires for a partial write.
    //
    // ENOENT is the whole of that argument, so it is the whole of what this
    // rewrites. Every other errno is a file that WAS written and could not be
    // read — a mode that denies it, or the descriptor table exhausted under a
    // parallel suite — and the crafted sentence would be a false claim about
    // what PowerShell did, sending the reader after a non-terminating error
    // record that never happened. Those keep their own error, and their errno
    // with it.
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    throw new Error(`Compress-Archive reported success but wrote nothing to ${archivePath}`, {
      cause: err,
    });
  }
  try {
    const buf = Buffer.alloc(4);
    const read = readSync(fd, buf, 0, 4, 0);
    if (read < 4 || buf.toString('hex') !== '504b0304') {
      throw new Error(
        `Compress-Archive reported success but ${archivePath} is not a zip — ` +
          `read ${String(read)} byte(s), starting ${buf.subarray(0, read).toString('hex')}`,
      );
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * Run one `Compress-Archive`, retrying the CLR aborts that PowerShell raises on
 * some hosts for a command that is correct.
 *
 * On at least one CI runner architecture, `pwsh` intermittently dies before
 * `Compress-Archive` does anything, with a `FileLoadException` naming an
 * assembly whose PublicKeyToken has been TRUNCATED mid-string. The token is a
 * fixed 16-hex-digit constant, so a short one is not a version mismatch or a
 * missing module — it is a corrupted read of the assembly name, and the process
 * aborts rather than exiting. It is not the command: the same call succeeds on
 * the next attempt, and succeeds on other legs of the same run against the same
 * commit; one observed job had one call abort and another complete.
 *
 * So the retry is keyed on the SIGNAL, which is what makes it narrow. A child
 * killed by a signal reports `status: null, signal: 'SIGABRT'`, while every way
 * `Compress-Archive` can genuinely fail — a path that does not exist, a
 * destination that cannot be written, a module it cannot autoload — is caught by
 * PowerShell and leaves through a non-zero EXIT, i.e. `status: <n>, signal:
 * null`. A missing interpreter is different again (`code: 'ENOENT'`), and is
 * already handled by the caller before this is reached. None of those is
 * retried: they rethrow on the first attempt, unchanged.
 *
 * The destination is removed before every attempt rather than relying on
 * `-Force`, and that is a line this fixture had been missing rather than a new
 * precaution: archive-sea.mjs — the script the comment below says this mirrors —
 * runs `rmSync(archivePath, { force: true })` immediately before the same
 * cmdlet. The mirror had copied the Compress-Archive and dropped the unlink.
 *
 * It matters more with a retry than without one. `-Force` only permits
 * clobbering, and it is applied when the destination stream is opened — AFTER
 * parameter binding and module autoload, which is where this abort fires. So an
 * attempt that dies early never reaches it, and a truncated file from an earlier
 * attempt survives untouched. What consumes this is `writeRelease`, which hashes
 * whatever bytes are on disk into SHA256SUMS: a truncated archive would be
 * listed CORRECTLY, leaving a release that verifies against itself and proves
 * nothing. Starting every attempt from no file at all makes that unreachable
 * rather than unlikely.
 */
export function compressArchive(
  exe: string,
  root: string,
  archivePath: string,
  // Injectable for the same reason `publishByRename`'s mover is: the abort this
  // exists for cannot be provoked on demand, so driven against a real pwsh the
  // retry branch is dead code on every leg that runs these tests.
  run: CompressRunner = runCompress,
): void {
  // Mirrors archive-sea.mjs's Compress-Archive, with -CompressionLevel
  // NoCompression added: the installer only hashes the archive and expands it,
  // and neither step cares whether the entries were deflated, so every cycle
  // spent compressing buys the fixture nothing but wall clock. This read
  // `Fastest` first, which reasons the same way but stops one step short —
  // `Fastest` still deflates, and it is deflating the ~115 MB Node binary the
  // runnable archive carries, on the platform with the most expensive fsync of
  // the three. `NoCompression` stores instead, and `Expand-Archive` reads a
  // stored zip exactly the same way.
  const args = [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    `Compress-Archive -Force -CompressionLevel NoCompression -Path '${root}' -DestinationPath '${archivePath}'`,
  ];

  for (let attempt = 1; ; attempt += 1) {
    // Never inherited from a previous attempt — see the note above on why a
    // partial archive here would be worse than the abort.
    rmSync(archivePath, { force: true });
    try {
      run(exe, args);
      assertZipWritten(archivePath);
      return;
    } catch (err) {
      const signal = (err as { signal?: NodeJS.Signals | null }).signal;
      // The budget is spent, or this is not the abort: the caller owns it, and
      // gets the ORIGINAL error rather than one describing the retry.
      if (attempt >= COMPRESS_ATTEMPTS || signal !== RETRYABLE_SIGNAL) throw err;
    }
  }
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
  // Seams, so a test can prove this function is really WIRED to the retry.
  // Exercised only through an injected runner one level down, every assertion
  // about the retry stays green if this call site is reverted to a bare spawn —
  // which is the one change that would put the flake back. `exe` is injectable
  // with it because the interpreter is resolved here: without it the wiring
  // could only be checked on a host that has PowerShell, i.e. not on the legs
  // where the retry branch would otherwise be dead code.
  { exe: exeOverride, run }: { exe?: string; run?: CompressRunner } = {},
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
      const exe = exeOverride ?? powershellExe();
      if (exe === undefined) {
        throw new Error(
          `cannot build ${archiveNameFor(version, triple)}: a zip fixture needs a PowerShell ` +
            '(Compress-Archive), and this host has neither `powershell` nor `pwsh`',
        );
      }
      compressArchive(exe, root, archivePath, run);
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
    // tar/Compress-Archive just read from `stage`, and a straggler holding a
    // file open under it is a Windows sharing violation the removal has to
    // tolerate rather than fail the fixture on.
    removeTree(stage);
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
