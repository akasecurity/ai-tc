import { defineConfig } from 'vitest/config';

// exception.test.ts and dashboard.test.ts exercise real node:sqlite file I/O,
// The CLI suite exercises real node:sqlite file I/O, which runs slowly under
// Turbo's parallel task load, so raise the per-test AND per-hook timeouts
// per-test AND per-hook timeouts above vitest's 5s/10s defaults (mirrors
// packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
