import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    // No timeout overrides: this suite is synchronous assertions with no child
    // process, no store and no migration template, so it runs on vitest's own
    // defaults — which is why the package is absent from the ratchet's TIMEOUTS.
    environment: 'node',
  },
});
