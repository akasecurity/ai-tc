import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// web-ui's first test runner. The Server Action suites exercise the REAL
// node:sqlite store and the REAL fingerprint key file (no database mocking —
// the repository's house style), which runs slowly under Turbo's parallel task
// load, so raise the per-test AND per-hook timeouts above vitest's 5s/10s
// defaults (mirrors cli/vitest.config.ts and packages/persistence/vitest.config.ts).
//
// `server-only` is aliased to an empty module: app/lib/db imports it, and the
// real package throws at import time when loaded outside a React Server bundler.
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
    alias: {
      'server-only': fileURLToPath(new URL('./test/setup/server-only-stub.ts', import.meta.url)),
    },
  },
});
