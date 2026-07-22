import { defineConfig } from 'vitest/config';

// The rule timing tests exercise real ReDoS backtracking behavior via checkRuleTiming
// and filterUnsafeRules; catastrophic patterns can take well over a second to evaluate
// on the Windows CI runner, so raise the per-test AND per-hook timeouts above vitest's
// 5s/10s defaults to leave headroom under parallel load (mirrors packages/persistence
// and packages/plugin-runtime for the same reason under heavy workspace contention).
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
