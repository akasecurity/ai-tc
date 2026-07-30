import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// globalSetup builds scripts/*.js once, in the main process, before any worker
// runs — the journey harness (test/journey) drives those built scripts.
//
// The journey tests spawn those built scripts as real child processes, which
// runs slowly under Turbo's parallel task load, so raise the
// per-test AND per-hook timeouts above vitest's 5s/10s defaults (mirrors
// packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    environment: 'node',
    globalSetup: ['./test/journey/global-setup.ts'],
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
