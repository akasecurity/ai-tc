import { defineConfig } from 'vitest/config';

// Real FS + gateway work runs slowly on the Windows CI runner under parallel
// load, so raise the per-test AND per-hook timeouts above vitest's 5s/10s
// defaults (mirrors packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
