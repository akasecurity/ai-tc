import { defineConfig } from 'vitest/config';

// The session-start and gateway suites exercise real node:sqlite file I/O; those
// DB-backed tests run well over a second each on the Windows CI runner, so raise
// the per-test timeout above vitest's 5s default to leave headroom under parallel
// load (mirrors packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20000,
  },
});
