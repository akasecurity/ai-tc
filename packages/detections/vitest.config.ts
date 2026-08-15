import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    // The ReDoS gate deliberately runs patterns that are slow by design: a
    // planted catastrophic rule can take ~1.5s to detect locally, and the
    // Windows runner is ~3x slower (it already timed out once on the 5s
    // default). Match the DB-heavy suites (persistence, plugin-runtime,
    // local-ops), which raise the timeout for the same reason.
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
