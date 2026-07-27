import { defineConfig } from 'vitest/config';

// The suite exercises real node:sqlite file I/O; the fixture-heavy tests run
// well over a second each on the Windows CI runner, so raise the per-test AND
// per-hook timeouts above vitest's 5s/10s defaults to leave headroom under
// parallel load (setup hooks open the DB + load fixtures and are just as slow).
// `sequence.hooks` is pinned rather than inherited: useTempStore registers its
// own beforeEach/afterEach around a suite's, and only 'stack' runs its teardown
// after the suite's own. Under 'list' or 'parallel' the store would be
// destroyed first, and a suite reading it in teardown would break with no
// compile-time signal.
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20000,
    hookTimeout: 20000,
    sequence: { hooks: 'stack' },
  },
});
