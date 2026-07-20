import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Builds the plugin's scripts/*.js once before the suite runs. The journey
// harness spawns those built scripts; Vitest runs globalSetup in the main process
// to completion before any test worker starts, so the build finishes before any
// worker can spawn a script — no worker ever reads a script mid-rewrite. Runs
// once per `vitest run`, not per worker or per test file.
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

export function setup(): void {
  execFileSync('pnpm', ['run', 'build'], { cwd: PLUGIN_ROOT, stdio: 'pipe' });
}
