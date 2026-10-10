import { fileURLToPath } from 'node:url';

import { configDefaults, defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));
// And on a machine with no ADMINISTRATOR, declared for the same reason: the
// managed overlay is read from absolute system paths that a temp home cannot
// redirect, so without this a suite reads whatever the developer's own laptop
// is enrolled in. See the guard for why a per-call override cannot cover it.
const noManagedSettingsGuard = fileURLToPath(
  new URL('../../test/setup/no-managed-settings.ts', import.meta.url),
);

// globalSetup builds scripts/*.js once, in the main process, before any worker
// runs — the journey harness (test/journey) drives those built scripts.
//
// The journey tests spawn those built scripts as real child processes, which
// runs slowly under Turbo's parallel task load, so raise the
// per-test AND per-hook timeouts above vitest's 5s/10s defaults (mirrors
// packages/persistence/vitest.config.ts).
export default defineConfig({
  resolve: {
    // engine-entry.ts imports the rule data build/engine.mjs generates; the stub
    // computes the same data in-process so the source is testable directly.
    alias: {
      'aka:parsed-packs': fileURLToPath(
        new URL('./test/mod/parsed-packs-stub.ts', import.meta.url),
      ),
    },
  },
  test: {
    setupFiles: [noNetworkGuard, noManagedSettingsGuard],
    // hooks/mod.ts runs inside Claude Code's mod runtime, never in Node; the
    // "Claude Code · Mod runtime" CI job (`claude plugin test`) is what covers it.
    coverage: coverageOptions(import.meta.url),
    // test/mod-runtime runs under `claude plugin test`, not vitest.
    exclude: [...configDefaults.exclude, 'test/mod-runtime/**'],
    environment: 'node',
    globalSetup: ['./test/journey/global-setup.ts'],
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
