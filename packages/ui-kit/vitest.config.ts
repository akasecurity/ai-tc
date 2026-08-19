import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// ui-kit had no test script at all until coverage landed, which is why its zero
// was invisible: `turbo run test` skips a package with no `test` script and
// exits 0, so the package reported nothing rather than reporting none.
//
// `environment: 'node'` is deliberate and is NOT an oversight to be "fixed" by
// switching to jsdom. Nothing here mounts a component — the suite covers the
// one piece of behaviour in the package that is logic rather than markup. A
// renderer tier is the right way to cover the components themselves, and it is
// a different job from making this package's number visible.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
