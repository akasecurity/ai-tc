import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
//
// This package is the one whose PRODUCT job is to reach the registry, so it is
// worth being precise: `pnpm audit`/`npm audit` run as child processes, which
// the guard structurally cannot see, and these tests drive the gate's parsing
// and waiver logic rather than the audits themselves. The guard is here to keep
// that true — an in-process reach for the network from this suite is a defect.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
