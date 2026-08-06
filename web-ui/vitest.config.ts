import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../test/setup/no-network.ts', import.meta.url));

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
//
// `oxc.jsx` overrides tsconfig.json's `"jsx": "preserve"`, which Next requires
// (its own compiler consumes the untransformed JSX) and which vitest otherwise
// inherits — leaving JSX in the output for a parser that then rejects it. Any
// test importing a page or a component fails at parse time without this, so a
// route's data derivation could only be tested by reading its source as text.
// It applies to `.tsx` alone; the suites that import no component are unchanged.
export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  test: {
    setupFiles: [noNetworkGuard],
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
    include: ['test/**/*.test.ts'],
    alias: {
      'server-only': fileURLToPath(new URL('./test/setup/server-only-stub.ts', import.meta.url)),
    },
  },
});
