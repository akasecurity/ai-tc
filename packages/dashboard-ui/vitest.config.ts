import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

// The shared views are presentational; almost every suite here covers the pure
// helpers (meta/matcher logic) or server-renders a view via react-dom/server,
// so node is the right default and the package pays for no DOM.
//
// The exception is useRenderClock, whose whole point is what happens AFTER
// hydration — invisible to a server render, which runs no effect and no store
// subscription. That suite opts into jsdom with a `@vitest-environment jsdom`
// docblock of its own (and `jsdom` is a devDependency for it). Keep any further
// DOM-needing suite on that per-file opt-in rather than switching this default:
// the rest of the package gains nothing from a DOM but the time to build one.
export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
  },
});
