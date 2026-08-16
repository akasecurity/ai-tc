import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// No package-wide timeout override on purpose. The slow work here is config
// resolution, which is confined to `beforeAll` hooks that carry their own
// budgets (no-network.test.js's CONFIG_LOAD_TIMEOUT_MS, effective-config.test.js's
// RESOLVE_TIMEOUT_MS). Raising testTimeout for the package would spend that
// budget on ~112 fixture-lint assertions that each run in well under a
// millisecond, where a regression to multiple seconds should fail rather than
// pass quietly.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
