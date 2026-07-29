import { spawnSync } from 'node:child_process';
import { constants } from 'node:os';

// Git-style external subcommand dispatch: an `aka <command>` invocation that
// matches no built-in runs an executable named `aka-<command>` from the
// caller's PATH, passing the remaining argv through verbatim.

// Does a command resolve on PATH? Runs `command -v` through `sh` with the name
// as a positional argument rather than `shell: true`, which concatenates its
// arguments into the command string and is deprecated on current Node.
export function commandOnPath(command: string): boolean {
  const probe = spawnSync('/bin/sh', ['-c', 'command -v "$1" >/dev/null 2>&1', 'sh', command], {
    stdio: 'ignore',
  });
  return probe.status === 0;
}

// The subset of spawnSync the dispatcher uses, injectable for tests.
export type ExternalSpawn = (
  command: string,
  args: string[],
  options: { stdio: 'inherit' },
) => { status: number | null; signal?: NodeJS.Signals | null; error?: NodeJS.ErrnoException };

export interface ExternalDispatchResult {
  found: boolean;
  status: number;
}

export interface ExternalDispatchDeps {
  spawn?: ExternalSpawn;
  platform?: NodeJS.Platform;
  // Whether a command resolves on PATH. Used only to tell a missing executable
  // apart from one that exists but cannot start.
  exists?: (command: string) => boolean;
}

// A name eligible for external dispatch: a lowercase letter followed by
// lowercase letters, digits, or hyphens. Excludes hidden `__*` commands,
// flag-like strings, path separators, and uppercase.
export function isExternalCommandName(name: string): boolean {
  return /^[a-z][a-z0-9-]*$/.test(name);
}

// Built-ins always win: a name backed by a built-in handler never dispatches
// externally, even when a matching `aka-<command>` executable is on PATH.
export function shouldDispatchExternal(command: string, isBuiltin: boolean): boolean {
  return !isBuiltin && isExternalCommandName(command);
}

// External dispatch is available on POSIX only. On Windows a bare command name
// resolves against the child's cwd before PATH, and `.cmd` shims need
// `shell: true` to spawn at all; dispatch must preserve the caller's cwd, so it
// stays off there and the normal unknown-command error prints instead.
export function externalDispatchSupported(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== 'win32';
}

// A signal-terminated child has no exit status. Report it the way a shell does,
// as 128 + the signal number, so callers can tell an interrupt (130) or a crash
// (139) apart from an ordinary failure.
export function signalExitCode(signal: NodeJS.Signals | null | undefined): number {
  const number = signal ? constants.signals[signal] : undefined;
  return number === undefined ? 1 : 128 + number;
}

// Run `aka-<command>` with the child inheriting stdio and the caller's cwd and
// environment. `found: false` means no such executable exists and the caller
// should fall through to its unknown-command error.
export function dispatchExternal(
  command: string,
  argv: string[],
  deps: ExternalDispatchDeps = {},
): ExternalDispatchResult {
  const spawn: ExternalSpawn = deps.spawn ?? spawnSync;
  const platform: NodeJS.Platform = deps.platform ?? process.platform;
  const exists: (command: string) => boolean = deps.exists ?? commandOnPath;
  if (!externalDispatchSupported(platform)) return { found: false, status: 1 };

  const target = `aka-${command}`;
  const result = spawn(target, argv, { stdio: 'inherit' });

  if (result.error) {
    // ENOENT means either no such executable on PATH or one whose interpreter is
    // missing — a shebang naming an absent absolute path reports the same code.
    // Probe PATH to tell them apart, so a broken executable is reported as a
    // failure rather than as a command the user never installed.
    if (result.error.code === 'ENOENT' && !exists(target)) return { found: false, status: 1 };
    process.stderr.write(`aka: ${target}: ${result.error.message}\n`);
    return { found: true, status: 1 };
  }

  if (result.status === null) {
    if (result.signal) process.stderr.write(`aka: ${target}: terminated by ${result.signal}\n`);
    return { found: true, status: signalExitCode(result.signal) };
  }

  return { found: true, status: result.status };
}
