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

export function setup(): void {
  execFileSync('pnpm', ['run', 'build'], { cwd: PACKAGE_ROOT, stdio: 'pipe' });
}
