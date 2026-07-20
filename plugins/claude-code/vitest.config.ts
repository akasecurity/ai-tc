import { defineConfig } from 'vitest/config';

// globalSetup builds scripts/*.js once, in the main process, before any worker
// runs — the journey harness (test/journey) drives those built scripts.
export default defineConfig({
  test: {
    environment: 'node',
    globalSetup: ['./test/journey/global-setup.ts'],
  },
});
