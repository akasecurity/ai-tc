import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Builds the plugin's scripts/*.js once before the suite runs. The onboard and
// start-light suites spawn those built scripts; Vitest runs globalSetup in the
// main process to completion before any test worker starts, so the build
// finishes before any worker can spawn a script — no worker ever reads a script
// mid-rewrite. Runs once per `vitest run`, not per worker or per test file.
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// On Windows `pnpm` is a `.cmd` shim: execFile does no PATHEXT resolution and
// (since the CVE-2024-27980 fix) refuses to spawn a `.cmd` without a shell, so
// a bare execFileSync here fails before a single test runs. Route through
// cmd.exe there — the same trade packages/local-ops/src/exec.ts makes, and safe
// for the same reason: the args are constants with no shell metacharacters.
// (Node warns DEP0190 for args-with-shell; it is a runtime notice on stderr,
// not a failure, and it fires on Windows only.) POSIX stays shell-free.
const USE_SHELL = process.platform === 'win32';

export function setup(): void {
  execFileSync('pnpm', ['run', 'build'], {
    cwd: PLUGIN_ROOT,
    stdio: 'pipe',
    shell: USE_SHELL,
  });
}
