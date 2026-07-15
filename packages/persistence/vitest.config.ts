import { defineConfig } from 'vitest/config';

// The suite exercises real node:sqlite file I/O; the fixture-heavy tests run
// well over a second each on the Windows CI runner, so raise the per-test
// timeout above vitest's 5s default to leave headroom under parallel load.
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20000,
  },
});
