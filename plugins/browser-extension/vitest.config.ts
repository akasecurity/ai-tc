import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    // Builds dist/ and native-host/ once, in the main process, before any
    // worker starts — the scan-worker bundle suite drives the built artifacts.
    globalSetup: ['./test/global-setup.ts'],
    environment: 'node',
  },
});
