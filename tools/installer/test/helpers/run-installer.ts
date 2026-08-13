// Spawns the SHIPPED install scripts exactly as a user's shell would: the real
// tools/installer/install.sh under `sh`, the real install.ps1 under PowerShell,
// with only the documented AKA_* overrides layered on. Nothing here reimplements
// a step of either script — the whole point of this package is that the scripts
// themselves run.
import { spawn, spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// tools/installer — the two scripts under test sit at this package's root.
// Exported because script-encoding.test.ts reads the same two files rather than
// spawning them, and a second derivation of where they live is a guard that can
// silently start checking nothing.
const INSTALLER_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const INSTALL_SH = join(INSTALLER_DIR, 'install.sh');
export const INSTALL_PS1 = join(INSTALLER_DIR, 'install.ps1');

// The host env, read once so the spawned scripts inherit PATH and find curl /
// tar / shasum — the one sanctioned reason to touch it here (mirrors
// plugins/claude-code/test/helpers/run-hook.ts).
// eslint-disable-next-line n/no-process-env -- test harness needs host PATH to spawn the real scripts
const HOST_ENV = process.env;

// A proxy configured on the host would intercept the loopback fetch, so a
// fixture the server does serve could come back as a proxy error — a refusal for
// a reason this suite invented rather than one either script decided.
const NO_PROXY = { no_proxy: '127.0.0.1,localhost', NO_PROXY: '127.0.0.1,localhost' } as const;

/**
 * The host env with `PSModulePath` removed, for a Windows PowerShell child.
 *
 * PowerShell autoloads its own core modules off `PSModulePath`, and the two
 * editions do NOT share one: pwsh 7 points it at `…\PowerShell\7\Modules` while
 * Windows PowerShell 5.1 needs `…\WindowsPowerShell\v1.0\Modules`. Inheriting
 * one edition's value into the other therefore costs the child its own standard
 * library — `Get-FileHash` (Microsoft.PowerShell.Utility) stops resolving, and
 * the script dies at the hashing step with `CommandNotFoundException`.
 *
 * That is not hypothetical here: GitHub Actions runs Windows `run:` steps under
 * pwsh by DEFAULT, so every spawn from this suite handed 5.1 a pwsh-7 module
 * path until this existed. Dropping the variable lets each edition compute its
 * own default, which is what a user's own shell gives it — and this harness's
 * whole contract is to spawn the scripts as a user's shell would.
 *
 * Deleted case-insensitively on purpose. Windows env names are case-insensitive
 * and `process.env` preserves whatever casing the parent used, but a spread copy
 * is a plain object where `delete env.PSModulePath` matches one spelling only.
 */
export function powershellEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const merged: NodeJS.ProcessEnv = { ...HOST_ENV, ...extra };
  return Object.fromEntries(
    Object.entries(merged).filter(([key]) => key.toLowerCase() !== 'psmodulepath'),
  );
}

/**
 * A directory holding REAL release archives, or undefined.
 *
 * The suite's own fixture packs a stub, which is all the installer's plumbing
 * needs — it hashes, extracts and links whatever the archive holds. Pointing
 * this at `cli/sea-dist` after `archive:sea` drives the same scripts against the
 * artifact a user would actually download, which is what build-binaries.yml
 * does on every supported target. Absent, that one case skips.
 *
 * It lives beside the spawn helpers rather than with the fixture builders so
 * this package reads the host environment in exactly one file.
 */
export function realDistDir(): string | undefined {
  // eslint-disable-next-line n/no-process-env -- see HOST_ENV above; this is the same boundary
  const dir = process.env.AKA_INSTALLER_REAL_DIST;
  return dir === undefined || dir === '' ? undefined : dir;
}

/**
 * Whether the caller has consented to install.ps1 rewriting the HKCU `Path`.
 *
 * Every case that lets install.ps1 reach step 6 mutates a real, persistent
 * user-scope environment variable, and the restore this suite performs is not
 * quite lossless: reading through `[Environment]::GetEnvironmentVariable`
 * expands any `%VAR%` reference, and writing back stores the expanded result as
 * a plain string. A Windows contributor running `pnpm test` would have their
 * `Path` flattened by a suite they only meant to run, and a run killed before
 * the `finally` would leave a temp directory on it as well.
 *
 * So the mutating cases are opt-in, exactly as {@link realDistDir} gates the
 * real-archive case: CI sets this and keeps the coverage, a workstation does
 * not and skips it. The expansion itself is install.ps1's own behaviour on
 * every user who installs, not something this suite introduces — that is a
 * separate defect, tracked separately.
 */
export function userPathOptIn(): boolean {
  // eslint-disable-next-line n/no-process-env -- see HOST_ENV above; this is the same boundary
  return process.env.AKA_INSTALLER_ALLOW_USER_PATH === '1';
}

export interface InstallerRun {
  /** The script's exit status; null if it was killed by a signal. */
  status: number | null;
  stdout: string;
  stderr: string;
}

export interface InstallerOverrides {
  /** AKA_DOWNLOAD_BASE — the fixture server's URL. */
  base: string;
  /** AKA_VERSION — required whenever AKA_DOWNLOAD_BASE is set. */
  version: string;
  /** AKA_INSTALL_DIR — where a version is extracted. */
  installDir: string;
  /** AKA_BIN_DIR — where install.sh links `aka`. POSIX only. */
  binDir?: string;
}

/** Fail loudly on a spawn that never started; a silent null status reads as a refusal. */
function toRun(command: string, result: SpawnSyncReturns<string>): InstallerRun {
  if (result.error !== undefined) {
    throw new Error(`could not spawn ${command}: ${result.error.message}`);
  }
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/**
 * Run a script to completion, ASYNCHRONOUSLY, and collect its output.
 *
 * The async form is load-bearing and not a style choice. The fixture release is
 * served by an HTTP server on this very event loop, so a `spawnSync` here
 * DEADLOCKS: the child's `curl` opens a connection the parent cannot answer
 * until the synchronous call it is blocked inside returns. Every other spawn in
 * this package is fine synchronous because none of them is waiting on the
 * server.
 *
 * A `timeout` is passed rather than left to vitest: a script that never exits
 * would otherwise burn the whole 120 s testTimeout and — because vitest fails
 * the test without touching the child — leave the spawned `sh`/`curl` running
 * after the run. SIGKILL because the point is to stop it, not to ask.
 */
const SCRIPT_TIMEOUT_MS = 60_000;

async function runScript(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<InstallerRun> {
  return await new Promise<InstallerRun>((resolve, reject) => {
    const child = spawn(command, args, {
      env,
      timeout: SCRIPT_TIMEOUT_MS,
      killSignal: 'SIGKILL',
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    child.on('error', (err) => {
      reject(new Error(`could not spawn ${command}: ${err.message}`));
    });
    child.on('close', (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}

/** Run the real install.sh against a fixture base. */
export async function runInstallSh({
  base,
  version,
  installDir,
  binDir,
}: InstallerOverrides): Promise<InstallerRun> {
  return await runScript('sh', [INSTALL_SH], {
    ...HOST_ENV,
    ...NO_PROXY,
    AKA_DOWNLOAD_BASE: base,
    AKA_VERSION: version,
    AKA_INSTALL_DIR: installDir,
    ...(binDir === undefined ? {} : { AKA_BIN_DIR: binDir }),
  });
}

/**
 * A PowerShell that can run install.ps1, or undefined when the host has none.
 *
 * Windows PowerShell 5.1 wins on win32: it is what a user piping the one-liner
 * into `iex` actually has, and it is the interpreter install.ps1's own comments
 * are written against. `pwsh` is the fallback, which is what lets the refusal
 * cases — the ones that exit before anything Windows-only — run on a developer
 * machine or in a container.
 *
 * It PERFORMS the resolution rather than modelling it. A probe that agreed with
 * a PATH model but not with the spawn would prove nothing about the spawn.
 *
 * Memoized: the answer cannot change inside one process, and every call is a
 * process spawn — the slowest thing available on the Windows runner. Three test
 * modules ask at load and every win32 fixture build asks again. Boxed rather
 * than stored bare, so a host with NO PowerShell caches that answer too instead
 * of re-probing on every call.
 */
let resolvedPowershell: { exe: string | undefined } | undefined;

export function powershellExe(): string | undefined {
  if (resolvedPowershell !== undefined) return resolvedPowershell.exe;
  resolvedPowershell = { exe: probePowershell() };
  return resolvedPowershell.exe;
}

function probePowershell(): string | undefined {
  for (const command of process.platform === 'win32' ? ['powershell', 'pwsh'] : ['pwsh']) {
    const probe = spawnSync(command, ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], {
      encoding: 'utf8',
      env: powershellEnv(),
    });
    if (probe.error === undefined && probe.status === 0) return command;
  }
  return undefined;
}

/** Run the real install.ps1 against a fixture base, under `exe`. */
export async function runInstallPs1(
  exe: string,
  { base, version, installDir }: InstallerOverrides,
): Promise<InstallerRun> {
  return await runScript(
    exe,
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', INSTALL_PS1],
    powershellEnv({
      ...NO_PROXY,
      AKA_DOWNLOAD_BASE: base,
      AKA_VERSION: version,
      AKA_INSTALL_DIR: installDir,
      // On win32 the runner already reports its own architecture and this must
      // not overwrite it — a lie there would skip the unsupported-arch refusal
      // the script is entitled to make. Off win32 there is no such variable,
      // and the refusal cases need step 1 to pass to reach step 4 at all.
      ...(process.platform === 'win32' ? {} : { PROCESSOR_ARCHITECTURE: 'AMD64' }),
    }),
  );
}

/**
 * The persisted USER `Path`, or null when the account has none.
 *
 * install.ps1 rewrites this for real — there is no override for it — so the
 * Windows happy path snapshots it here and puts it back afterwards. See the
 * caveat in install-ps1.test.ts.
 */
export function readUserPath(exe: string): string | null {
  const result = spawnSync(
    exe,
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "$p = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $p) { 'ABSENT' } else { 'PRESENT' + $p }",
    ],
    { encoding: 'utf8', env: powershellEnv() },
  );
  const run = toRun(`${exe} (read user Path)`, result);
  if (run.status !== 0) throw new Error(`could not read the user Path: ${run.stderr}`);
  const value = run.stdout.replace(/\r?\n$/u, '');
  return value === 'ABSENT' ? null : value.slice('PRESENT'.length);
}

/** Put a snapshot from {@link readUserPath} back. A null snapshot removes the variable. */
export function writeUserPath(exe: string, value: string | null): void {
  // The value travels in the child's environment rather than inside the command
  // string: a user Path is full of backslashes, semicolons and spaces, and
  // quoting it into `-Command` is a way to corrupt the thing being restored.
  const result = spawnSync(
    exe,
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "[Environment]::SetEnvironmentVariable('Path', $(if ($env:AKA_RESTORE_ABSENT -eq '1') { $null } else { $env:AKA_RESTORE_VALUE }), 'User')",
    ],
    {
      encoding: 'utf8',
      env: powershellEnv({
        AKA_RESTORE_ABSENT: value === null ? '1' : '0',
        AKA_RESTORE_VALUE: value ?? '',
      }),
    },
  );
  const run = toRun(`${exe} (restore user Path)`, result);
  if (run.status !== 0) throw new Error(`could not restore the user Path: ${run.stderr}`);
}
