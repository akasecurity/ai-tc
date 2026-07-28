import { spawnSync } from 'node:child_process';

// Git-style external subcommand dispatch: an `aka <command>` invocation that
// matches no built-in runs an executable named `aka-<command>` from the
// caller's PATH, passing the remaining argv through verbatim.

// The subset of spawnSync the dispatcher uses, injectable for tests.
export type ExternalSpawn = (
  command: string,
  args: string[],
  options: { stdio: 'inherit' },
) => { status: number | null; error?: NodeJS.ErrnoException };

export interface ExternalDispatchResult {
  found: boolean;
  status: number;
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

// Run `aka-<command>` with the child inheriting stdio and the caller's cwd and
// environment. `found: false` means no such executable exists and the caller
// should fall through to its unknown-command error.
export function dispatchExternal(
  command: string,
  argv: string[],
  spawn: ExternalSpawn = spawnSync,
  platform: NodeJS.Platform = process.platform,
): ExternalDispatchResult {
  if (!externalDispatchSupported(platform)) return { found: false, status: 1 };

  const result = spawn(`aka-${command}`, argv, { stdio: 'inherit' });

  if (result.error) {
    // ENOENT: no `aka-<command>` on PATH — not an external command.
    if (result.error.code === 'ENOENT') return { found: false, status: 1 };
    // Anything else: the executable exists but failed to start. Surface the
    // failure instead of falling through to the unknown-command error.
    process.stderr.write(`aka: aka-${command}: ${result.error.message}\n`);
    return { found: true, status: 1 };
  }

  // A null status means the child was terminated by a signal.
  return { found: true, status: result.status ?? 1 };
}
