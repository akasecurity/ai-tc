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
// without a shell. Route through cmd.exe there. Our args are package names / flags
// with no shell metacharacters, so no quoting concern. POSIX stays shell-free.
const USE_SHELL = process.platform === 'win32';

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
    const stdout = execFileSync(command, args, {
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
    execFileSync(command, args, { stdio: 'inherit', shell: USE_SHELL, ...SPAWN_CWD });
    return true;
  } catch {
    return false;
  }
}
