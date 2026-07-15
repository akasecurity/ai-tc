import { defineConfig } from 'vitest/config';

// The session-start and gateway suites exercise real node:sqlite file I/O; those
// DB-backed tests run well over a second each on the Windows CI runner, so raise
// the per-test AND per-hook timeouts above vitest's 5s/10s defaults to leave
// headroom under parallel load (mirrors packages/persistence/vitest.config.ts;
// setup hooks open the DB and are just as slow under Windows-runner contention).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
