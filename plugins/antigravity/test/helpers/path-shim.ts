import { execFileSync } from 'node:child_process';
import { chmodSync, writeFileSync } from 'node:fs';
import { delimiter, join } from 'node:path';

/**
 * A controlled executable placed first on a child's PATH, so a suite driving a
 * BUILT script can fake the external command that script shells out to.
 *
 * This is the only way to fake such a command: the spawns live behind a process
 * boundary (`triage/judge.ts`'s `spawnClaude`, `provenance.ts`'s npm runner),
 * so their dependency-injection seams are in-process only and unreachable from
 * a test that runs the real built script.
 *
 * ## The shim fails OPEN, which is why every user of it must probe first
 *
 * A shim that does not land is NOT an `ENOENT`. Resolution simply continues
 * down the rest of PATH and finds the REAL installed binary — measured on a
 * POSIX host by joining PATH with the wrong separator, which resolved and ran
 * the real `claude`, returning that live binary's own error. For a judge stub
 * that means a suite quietly making a live model call with its seeded hits on
 * stdin; a sentinel checked afterwards reports the egress rather than
 * preventing it.
 *
 * So a caller asserts resolution BEFORE it drives anything —
 * `assertShimResolves` — and a failure there is a red setup, never a live call.
 *
 * ## Three ways a hand-rolled shim is POSIX-only
 *
 * 1. **Separator.** PATH is `:`-joined on POSIX and `;`-joined on Windows. A
 *    `:`-joined PATH on Windows is one malformed entry, so the shim dir is not
 *    on PATH at all. `shimmedPath` uses `path.delimiter`.
 * 2. **Extension.** An extensionless file with a `#!` line is executable on
 *    POSIX and unrunnable on Windows, which resolves a bare command name
 *    through `PATHEXT`. `writeCommandShim` writes a `.cmd` launcher there.
 * 3. **Mode bits.** `chmodSync(…, 0o755)` is a no-op on Windows, so a shim that
 *    relies on it has no executable bit to rely on. It is skipped there.
 *
 * Shared by this package's suites because they sit behind one package wall.
 * Across a wall it cannot be imported, so `plugins/claude-code` and
 * `plugins/codex` carry peer copies — each taking a `path-shim.test.ts`
 * with it, or `assertShimResolves` can be weakened back into a no-op with
 * every caller staying green.
 */

/**
 * The argument the resolution probe sends.
 *
 * Deliberately `--version` rather than a bespoke flag: when resolution has
 * FAILED, the probe itself is what lands on the real binary, and `--version` is
 * the one argument every candidate here answers locally, from its own package
 * metadata, without contacting a model or a registry. A bespoke flag would be
 * rejected — usually harmlessly — by an argument parser this repo does not own.
 */
export const SHIM_PROBE_ARG = '--version';

/**
 * How long the probe may take before the resolved binary is force-killed.
 *
 * Deliberately well under the 20s `testTimeout` every plugin package sets: the
 * probe runs inside a test body, so a deadline equal to vitest's own means
 * vitest wins the race and the refusal below — the entire point of failing
 * closed — is replaced by a bare "test timed out". A binary that has not
 * answered `--version` in ten seconds is not going to.
 */
const PROBE_TIMEOUT_MS = 10_000;

/** The token a shim prints for {@link SHIM_PROBE_ARG}, and nothing else does. */
export function shimMarker(command: string): string {
  return `AKA-TEST-SHIM-OK:${command}`;
}

/**
 * The prologue every shim body is written behind: the shebang and strict-mode
 * directive a POSIX shim needs, then the probe answer.
 *
 * The probe is answered FIRST — ahead of any sentinel write or argv parsing —
 * so probing can never be mistaken for an invocation by a suite asserting the
 * command was not spawned.
 */
function shimPrologue(command: string): string {
  return `#!/usr/bin/env node
'use strict';
// Answer the harness's resolution probe before doing anything else, so a probe
// is never recorded as an invocation.
if (process.argv.slice(2).includes(${JSON.stringify(SHIM_PROBE_ARG)})) {
  process.stdout.write(${JSON.stringify(shimMarker(command))});
  process.exit(0);
}
`;
}

/**
 * `basePath` with `binDir` prepended, joined the way the RUNNING platform joins
 * PATH. A literal `':'` here is the first of the three POSIX-only defects
 * above.
 *
 * An absent or empty `basePath` yields the bin dir ALONE, with no trailing
 * separator: an empty PATH entry is read as the current directory by execvp and
 * by libuv's own search, so the convenient-looking `${binDir}${delimiter}` would
 * quietly add the working directory to a search path whose whole purpose is that
 * only the shim is on it.
 */
export function shimmedPath(binDir: string, basePath: string | undefined): string {
  return basePath ? `${binDir}${delimiter}${basePath}` : binDir;
}

/**
 * Write `body` into `binDir` as something the platform will execute for the
 * bare name `command`, and return the file a caller would name in an error.
 *
 * POSIX gets the extensionless file the `#!` line makes runnable. Windows gets
 * the body as a plain `.js` beside a `<command>.cmd` launcher that runs it
 * under this process's own node — an absolute interpreter path, so the launcher
 * does not additionally depend on node being on the child's PATH.
 *
 * `platform` defaults to the running one and exists so both branches are
 * reachable from either host, the way `triage/judge.ts`'s `judgeEnv` takes one.
 * Writing the other platform's form is a resolution failure on this one, which
 * is what lets a POSIX runner drive the win32 branch against the real refusal
 * rather than against a description of it.
 */
export function writeCommandShim(
  binDir: string,
  command: string,
  body: string,
  platform: NodeJS.Platform = process.platform,
): string {
  const source = shimPrologue(command) + body;
  if (platform === 'win32') {
    const scriptPath = join(binDir, `${command}-shim.js`);
    writeFileSync(scriptPath, source);
    const launcherPath = join(binDir, `${command}.cmd`);
    // CRLF, because a batch file is read by cmd.exe. %~dp0 carries its own
    // trailing separator; %* forwards argv, and stdin passes through untouched.
    writeFileSync(
      launcherPath,
      `@echo off\r\n"${process.execPath}" "%~dp0${command}-shim.js" %*\r\n`,
    );
    // No chmod: it is a no-op on Windows, and PATHEXT decides what runs.
    return launcherPath;
  }
  const shimPath = join(binDir, command);
  writeFileSync(shimPath, source);
  chmodSync(shimPath, 0o755);
  return shimPath;
}

export interface ShimResolutionOptions {
  /**
   * Mirror the spawn this shim stands in for. Pass `true` wherever the code
   * under test spawns with `shell` — on Windows that is the difference between
   * resolving a `.cmd` and skipping it, so a probe that disagrees with its
   * subject is a false verdict in one direction or the other.
   */
  readonly shell?: boolean;
  /**
   * The working directory the spawn being stood in for will use, when it is not
   * this process's own.
   *
   * PATH is not the whole of resolution: Windows searches the working directory
   * BEFORE walking PATH, so a probe run from a different cwd than its subject
   * verifies a resolution the subject never performs — and a binary sitting in
   * the subject's cwd wins silently. Pass whatever `cwd` reaches the real spawn.
   */
  readonly cwd?: string;
}

/**
 * Refuse to continue unless the bare name `command` resolves to the shim under
 * `env.PATH`.
 *
 * Resolution is not modelled, it is PERFORMED — the probe spawns the command
 * the same way the code under test will, so it agrees about `PATHEXT` and about
 * every other rule a hand-rolled resolver would have to restate. `options.shell`
 * and `options.cwd` are the axes the CALLER must supply, because they belong to
 * the spawn being stood in for rather than to the shim, and the probe cannot
 * discover either: get one wrong and the probe faithfully performs a resolution
 * its subject never performs.
 *
 * Throws — loudly, and naming the cause — rather than returning a boolean: a
 * caller that forgets to check a boolean is back to the fail-open behaviour
 * this exists to remove.
 */
export function assertShimResolves(
  command: string,
  env: NodeJS.ProcessEnv,
  options: ShimResolutionOptions = {},
): void {
  const marker = shimMarker(command);
  // Assigned on both paths below — the success value, or the failed spawn's own
  // stdout, which may still carry the marker.
  let output: string;
  let spawnFailure: string | undefined;
  try {
    output = execFileSync(command, [SHIM_PROBE_ARG], {
      env,
      encoding: 'utf8',
      timeout: PROBE_TIMEOUT_MS,
      killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: options.shell ?? false,
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    });
  } catch (err) {
    // Narrowed rather than `unknown`: an unknown here stringifies to
    // [object Object] instead of the fields a reader needs.
    const e = err as {
      code?: string;
      status?: number;
      signal?: string;
      stdout?: string;
      stderr?: string;
    };
    // A non-zero exit still carries both streams, and stdout may hold the marker
    // — a shim that answered and then failed for its own reasons has resolved,
    // which is the only question being asked here. Reading it is what keeps a
    // real resolution from being reported as a miss.
    output = e.stdout ?? '';
    const status = e.status === undefined ? '(none)' : String(e.status);
    // stderr is the only thing that explains a genuine failure, so it belongs in
    // the one message written to diagnose one.
    const stderr = (e.stderr ?? '').trim();
    spawnFailure =
      `code=${e.code ?? '(none)'} status=${status} signal=${e.signal ?? '(none)'}` +
      (stderr === '' ? '' : ` stderr=${JSON.stringify(stderr.slice(0, 200))}`);
  }
  if (output.includes(marker)) return;

  const sawInstead =
    spawnFailure !== undefined
      ? `the spawn failed (${spawnFailure})`
      : `it answered ${JSON.stringify(output.trim().slice(0, 120))}`;
  throw new Error(
    [
      `PATH shim for "${command}" did not resolve to the test stub — ${sawInstead}.`,
      'This is a SETUP failure and the suite must not continue: a shim that does',
      'not land does NOT fail closed. Resolution carries on down PATH and finds',
      `the REAL installed "${command}", so driving the chain from here would make`,
      'a live call with the seeded fixtures as its input.',
      'On Windows the usual cause is that execFile does no PATHEXT resolution and',
      'refuses to spawn a .cmd/.bat without a shell (the CVE-2024-27980 fix) — see',
      "packages/local-ops/src/exec.ts's USE_SHELL for the same constraint in",
      'shipped code. On POSIX, check the shim is executable and that PATH was',
      'joined with path.delimiter.',
    ].join(' '),
  );
}
