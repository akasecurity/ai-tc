import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// No package-wide timeout override on purpose. Almost every case here is a
// sub-millisecond assertion over an already-resolved config, and raising
// testTimeout for the package would spend a multi-second budget on ~112
// fixture-lint assertions, where a regression to multiple seconds should fail
// rather than pass quietly.
//
// The slow work carries its OWN budget instead, named at each site rather than
// inherited: no-network.test.js's CONFIG_LOAD_TIMEOUT_MS and
// effective-config.test.js's RESOLVE_TIMEOUT_MS for config resolution in a
// `beforeAll`, and effective-config.test.js's HASH_TIMEOUT_MS for the turbo-hash
// case, which spawns dry runs from the test BODY. That last one is why this
// paragraph no longer says the slow work is confined to hooks: a slow case is
// allowed here, it just has to name its own deadline.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
