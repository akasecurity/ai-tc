import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// The shared views are presentational; the tests here cover the pure helpers
// (meta/matcher logic), so a node environment is enough — no DOM. Add jsdom +
// @testing-library here if component-render tests are introduced later.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    environment: 'node',
  },
});
