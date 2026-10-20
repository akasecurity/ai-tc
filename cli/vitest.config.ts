import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../test/vitest/coverage.ts';
import { unfinishedModulesReporter } from '../test/vitest/unfinished-modules-reporter.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../test/setup/no-network.ts', import.meta.url));
// And on a machine with no ADMINISTRATOR, declared for the same reason: the
// managed overlay is read from absolute system paths that a temp home cannot
// redirect, so without this a suite reads whatever the developer's own laptop
// is enrolled in. See the guard for why a per-call override cannot cover it.
const noManagedSettingsGuard = fileURLToPath(
  new URL('../test/setup/no-managed-settings.ts', import.meta.url),
);
// And with Claude Code's config pointed at an empty directory: `aka status`
// reads the login file under the real home unless a case names another, so
// without this a status block depends on whose laptop ran the suite.
const noHostClaudeConfigGuard = fileURLToPath(
  new URL('../test/setup/no-host-claude-config.ts', import.meta.url),
);
// And with Codex's home pointed at an empty directory and no Codex key, token or
// gateway address in the environment, for the same reason: the Codex line of
// `aka status` reads the login under the real home unless a case names another.
const noHostCodexConfigGuard = fileURLToPath(
  new URL('../test/setup/no-host-codex-config.ts', import.meta.url),
);

// And with wasm code GC off on Node 24: this suite can terminate a worker, and
// on that line freeing code after a termination can abort the test process.
// See the setup file; no-wasm-code-gc-guard.test.js derives which packages owe it.
const noWasmCodeGc = fileURLToPath(new URL('../test/setup/no-wasm-code-gc.ts', import.meta.url));

// The CLI suite exercises real node:sqlite file I/O, which runs slowly under
// Turbo's parallel task load, so raise the per-test AND per-hook timeouts above
// vitest's 5s/10s defaults (mirrors packages/persistence/vitest.config.ts).
export default defineConfig({
  plugins: [unfinishedModulesReporter()],
  test: {
    setupFiles: [
      noNetworkGuard,
      noManagedSettingsGuard,
      noHostClaudeConfigGuard,
      noHostCodexConfigGuard,
      noWasmCodeGc,
    ],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    testTimeout: 20_000,
    hookTimeout: 20_000,
  },
});
