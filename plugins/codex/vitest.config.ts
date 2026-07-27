import { defineConfig } from 'vitest/config';

// No globalSetup counterpart to the Claude Code plugin's: codex has no journey
// harness driving built scripts/*.js, so the suite needs neither the pre-build
// step nor its raised timeouts.
export default defineConfig({
  test: {
    environment: 'node',
  },
});
