import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));
// And on a machine with no ADMINISTRATOR, declared for the same reason: the
// managed overlay is read from absolute system paths that a temp home cannot
// redirect, so without this a suite reads whatever the developer's own laptop
// is enrolled in. See the guard for why a per-call override cannot cover it.
const noManagedSettingsGuard = fileURLToPath(
  new URL('../../test/setup/no-managed-settings.ts', import.meta.url),
);

// The suite exercises real node:sqlite file I/O; the fixture-heavy tests run
// well over a second each on the Windows CI runner, so raise the per-test AND
// per-hook timeouts above vitest's 5s/10s defaults to leave headroom under
// parallel load (setup hooks open the DB + load fixtures and are just as slow).
// `sequence.hooks` is pinned rather than inherited: useTempStore registers its
// own beforeEach/afterEach around a suite's, and only 'stack' runs its teardown
// after the suite's own. Under 'list' or 'parallel' the store would be
// destroyed first, and a suite reading it in teardown would break with no
// compile-time signal.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard, noManagedSettingsGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 20000,
    sequence: { hooks: 'stack' },
  },
});
