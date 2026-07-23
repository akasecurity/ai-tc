import { defineConfig } from 'vitest/config';

// globalSetup builds scripts/*.js once, in the main process, before any worker
// runs — the journey harness (test/journey) drives those built scripts.
//
// The journey tests spawn those built scripts as real child processes, which
// runs slowly under Turbo's parallel task load, so raise the
// per-test AND per-hook timeouts above vitest's 5s/10s defaults (mirrors
// packages/persistence/vitest.config.ts).
export default defineConfig({
  test: {
    environment: 'node',
    globalSetup: ['./test/journey/global-setup.ts'],
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
