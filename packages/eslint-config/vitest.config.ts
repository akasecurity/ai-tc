import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';
import { unfinishedModulesReporter } from '../../test/vitest/unfinished-modules-reporter.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// And with wasm code GC off on Node 24: this suite can terminate a worker, and
// on that line freeing code after a termination can abort the test process.
// See the setup file; no-wasm-code-gc-guard.test.js derives which packages owe it.
const noWasmCodeGc = fileURLToPath(new URL('../../test/setup/no-wasm-code-gc.ts', import.meta.url));

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
  plugins: [unfinishedModulesReporter()],
  test: {
    setupFiles: [noNetworkGuard, noWasmCodeGc],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
