import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
//
// This package reads one file and writes three; it opens no socket at all. The
// guard is here so that stays true — the rendered manifests name download URLs,
// and a suite that fetched one would be reaching the network to assert a string.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// No testTimeout/hookTimeout override: every case here renders text in memory or
// writes three small files into a temp dir, so vitest's own defaults bound them.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
