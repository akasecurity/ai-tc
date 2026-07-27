import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// web-ui's test runner, covering two suites with different needs.
//
// The Server Action suites exercise the REAL node:sqlite store and the REAL
// fingerprint key file (no database mocking — the repository's house style),
// which runs slowly under Turbo's parallel task load, so raise the per-test AND
// per-hook timeouts above vitest's 5s/10s defaults (mirrors cli/vitest.config.ts
// and packages/persistence/vitest.config.ts). middleware.ts is the other end of
// the range: a pure Host/x-forwarded-host gate — one anchored regex, no DOM and
// no I/O — that never needs the extra headroom. A literal match also has no
// URL-parser behaviour that could diverge from the Edge runtime the middleware
// ships on, so running it under node is faithful to what ships.
//
// `server-only` is aliased to an empty module: app/lib/db imports it, and the
// real package throws at import time when loaded outside a React Server bundler.
//
// `include` is pinned to test/ so `vitest run` never globs a built `.next/`
// (left by any `next build`) into the run.
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
    include: ['test/**/*.test.ts'],
    alias: {
      'server-only': fileURLToPath(new URL('./test/setup/server-only-stub.ts', import.meta.url)),
    },
  },
});
