import { defineConfig } from 'vitest/config';

// The dashboard's testable surface is server-side logic, not rendered React:
// middleware.ts is a pure Host/x-forwarded-host gate (no DOM, no I/O), so a
// node environment with the default timeouts is enough. When the Server Action
// suites land here (they touch real node:sqlite via @akasecurity/persistence),
// raise testTimeout/hookTimeout to 20_000 like persistence/local-ops so they do
// not flake on the Windows runner — the middleware tests never need it.
export default defineConfig({
  test: {
    environment: 'node',
  },
});
