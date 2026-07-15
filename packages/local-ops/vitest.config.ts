import { defineConfig } from 'vitest/config';

// One suite exercises real node:sqlite file I/O, which runs slowly on the Windows
// CI runner under parallel load, so raise the per-test AND per-hook timeouts above
// vitest's 5s/10s defaults (mirrors packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
