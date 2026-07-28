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

// Run `aka-<command>` with the child inheriting stdio and the caller's cwd and
// environment. `found: false` means no such executable exists and the caller
// should fall through to its unknown-command error.
export function dispatchExternal(
  command: string,
  argv: string[],
  spawn: ExternalSpawn = spawnSync,
  platform: NodeJS.Platform = process.platform,
): ExternalDispatchResult {
  // External dispatch is POSIX-only. On Windows, `.cmd` shims refuse to spawn
  // without `shell: true` (the CVE-2024-27980 fix), and a bare command name
  // resolves against the child's cwd BEFORE PATH — the hazard class
  // @akasecurity/local-ops' exec wrappers anchor against — while external
  // dispatch must preserve the caller's cwd. Report not-found so the normal
  // unknown-command error prints.
  if (platform === 'win32') return { found: false, status: 1 };

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
