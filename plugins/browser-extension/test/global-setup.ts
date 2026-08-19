import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Builds dist/ and native-host/ once before the suite runs. The scan-worker
// bundle suite drives those built artifacts, and turbo's `test` task already
// depends on `build` — but a direct `pnpm --filter … test` does not, and a
// bundle guard that silently skips because nothing was built is the same
// vacuous pass it exists to prevent. Vitest runs globalSetup in the main
// process to completion before any test worker starts, so no worker can read
// an artifact mid-write. Runs once per `vitest run`.
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// On Windows `pnpm` is a `.cmd` shim: execFile does no PATHEXT resolution and
// (since the CVE-2024-27980 fix) refuses to spawn a `.cmd` without a shell, so
// a bare execFileSync here fails before a single test runs. Route through
// cmd.exe there — the same trade packages/local-ops/src/exec.ts makes, and safe
// for the same reason: the args are constants with no shell metacharacters.
// (Node warns DEP0190 for args-with-shell; it is a runtime notice on stderr,
// not a failure, and it fires on Windows only.) POSIX stays shell-free.
//
// This package's `test` IS on the Windows leg, so the flag is load-bearing
// rather than anticipatory: without it the shim fails before a single test
// runs — a `.cmd` refusal in globalSetup, not an assertion anyone can read.
// It was carried here ahead of that filter entry landing, which is why adding
// the package to the leg was a one-line change; do not read that history as
// meaning the flag is still spare.
const USE_SHELL = process.platform === 'win32';

export function setup(): void {
  execFileSync('pnpm', ['run', 'build'], {
    cwd: PACKAGE_ROOT,
    stdio: 'pipe',
    shell: USE_SHELL,
  });
}
