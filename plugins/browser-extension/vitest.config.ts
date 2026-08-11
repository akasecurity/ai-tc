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
    // The scan-worker bundle suite spawns a real worker thread against those
    // built artifacts, which runs slowly under Turbo's parallel task load —
    // raise the per-test AND per-hook timeouts above vitest's 5s/10s defaults
    // (mirrors plugins/claude-code/vitest.config.ts for the same reason).
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
