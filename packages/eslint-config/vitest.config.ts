import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// These suites import every tracked ESLint config in the workspace, run the real
// linter over ~100 fixtures, and drive the CI egress script through stubbed
// PATHs. That is FS- and module-resolution-bound, and turbo runs all 14 package
// test tasks in parallel — so on a 2-core CI runner it takes many times what it
// takes on a developer machine. Raise the per-test AND per-hook timeouts above
// vitest's 5s/10s defaults (mirrors packages/scanner/vitest.config.ts).
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
