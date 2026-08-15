import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// The session-start and gateway suites exercise real node:sqlite file I/O; those
// DB-backed tests run well over a second each on the Windows CI runner, so raise
// the per-test AND per-hook timeouts above vitest's 5s/10s defaults to leave
// headroom under parallel load (mirrors packages/persistence/vitest.config.ts;
// setup hooks open the DB and are just as slow under Windows-runner contention).
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
