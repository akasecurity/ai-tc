import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // The ReDoS gate deliberately runs patterns that are slow by design: a
    // planted catastrophic rule can take ~1.5s to detect locally, and the
    // Windows runner is ~3x slower (it already timed out once on the 5s
    // default). Match the DB-heavy suites (persistence, plugin-runtime,
    // local-ops), which raise the timeout for the same reason.
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
