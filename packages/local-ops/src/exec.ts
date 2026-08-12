import { execFileSync, spawnSync } from 'node:child_process';
import { homedir } from 'node:os';

// Thin, fail-open wrappers around child_process for shelling out to `npm` and
// `claude`. The OSS surface never calls fetch() — all network access rides the
// package managers the user already trusts, so their existing ~/.npmrc auth and
// PATH resolution apply. Env is inherited, never read.

export interface RunResult {
  ok: boolean;
  stdout: string;
  stderr: string;
}

// On Windows the global `npm`/`claude` binaries are `.cmd` shims; `execFile` does no
// PATHEXT resolution and (since the CVE-2024-27980 fix) refuses to spawn `.cmd`/`.bat`
// without a shell. Route through cmd.exe there. POSIX stays shell-free.
const USE_SHELL = process.platform === 'win32';

// Node does NOT quote arguments when `shell: true` — it joins command and argv
// with single spaces and hands the string to cmd.exe, so every argument is
// re-parsed as shell syntax. That was harmless while every argument was a
// package name or a flag, and stopped being harmless once the CLI self-update
// began passing an install PREFIX: `C:\Users\First Last\AppData\Roaming\npm`
// splits at the space, and a directory named with `&` or `|` would be read as
// a command separator rather than as part of a path.
//
// So arguments are quoted for cmd on the shell path. Only an argument that
// needs it is touched, which keeps every existing spawn byte-identical to what
// it sent before. Windows forbids `"` in a path, so wrapping in double quotes
// is sufficient to make one a single literal token; `%` is left alone, since
// cmd expands `%VAR%` inside quotes too and no escaping of it is reliable in
// every context — a path containing a `%name%` that matches a real environment
// variable is the documented gap.
const NEEDS_QUOTING = /[\s&|^<>()"]/;

export function quoteForShell(arg: string): string {
  return NEEDS_QUOTING.test(arg) ? `"${arg.replaceAll('"', '""')}"` : arg;
}

function shellArgs(args: string[]): string[] {
  return USE_SHELL ? args.map(quoteForShell) : args;
}

// Windows resolves a bare command name by searching the child's working
// directory BEFORE PATH (cmd.exe search order; libuv's app-name lookup does the
// same), so a spawn must never inherit a cwd the user merely cd'd into — a
// planted `npm.cmd` in a cloned repo would run instead of the real tool. Anchor
// every Windows spawn in the user's home directory: nothing run here (global
// npm installs, `claude plugin …`, version probes) depends on the caller's cwd.
// POSIX PATH lookup never consults the cwd, so no anchor is needed there.
const SPAWN_CWD = process.platform === 'win32' ? { cwd: homedir() } : {};

// Is a command resolvable on PATH? Cross-platform via `where` (Windows) / `command
// -v` (POSIX). Best-effort — a false here just routes callers to a manual fallback.
export function binExists(command: string): boolean {
  const probe = process.platform === 'win32' ? 'where' : 'command';
  const args = process.platform === 'win32' ? [command] : ['-v', command];
  try {
    const res = spawnSync(probe, args, {
      stdio: 'ignore',
      shell: process.platform !== 'win32',
      ...SPAWN_CWD,
    });
    return res.status === 0;
  } catch {
    return false;
  }
}

// Run a command and capture its output. Never throws — a nonzero exit, a missing
// binary, or a timeout all resolve to `{ ok: false }`. `timeoutMs` guards the
// update check from hanging on a slow/offline registry.
export function runCapture(command: string, args: string[], timeoutMs = 15_000): RunResult {
  try {
    const stdout = execFileSync(command, shellArgs(args), {
      encoding: 'utf8',
      timeout: timeoutMs,
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: USE_SHELL,
      ...SPAWN_CWD,
    });
    return { ok: true, stdout: stdout.trim(), stderr: '' };
  } catch (err: unknown) {
    const e = err as { stdout?: unknown; stderr?: unknown };
    return {
      ok: false,
      stdout: typeof e.stdout === 'string' ? e.stdout.trim() : '',
      stderr: typeof e.stderr === 'string' ? e.stderr.trim() : '',
    };
  }
}

// Run a command with the user's terminal attached (progress streams through), for
// the mutating installs/updates. Returns whether it exited 0.
export function runInherit(command: string, args: string[]): boolean {
  try {
    execFileSync(command, shellArgs(args), { stdio: 'inherit', shell: USE_SHELL, ...SPAWN_CWD });
    return true;
  } catch {
    return false;
  }
}
