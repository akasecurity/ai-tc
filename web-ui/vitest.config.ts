import { defineConfig } from 'vitest/config';

// middleware.ts is a pure Host/x-forwarded-host gate — a single anchored regex,
// no DOM and no I/O — so a node environment with the default timeouts exercises
// it fully. A literal match has no URL-parser behaviour that could diverge from
// the Edge runtime the middleware ships on, so the node run is faithful to it.
// `include` is pinned to test/ so `vitest run` never globs a built `.next/`
// (left by any `next build`) into the run.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
