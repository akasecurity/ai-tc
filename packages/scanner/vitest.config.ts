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

// Real FS + gateway work runs slowly on the Windows CI runner under parallel
// load, so raise the per-test AND per-hook timeouts above vitest's 5s/10s
// defaults (mirrors packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard, noManagedSettingsGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
