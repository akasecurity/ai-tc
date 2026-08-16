import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

import { coverageOptions } from '../../test/vitest/coverage.ts';

// Every test file runs behind the no-network guard: it refuses any outbound
// connection that is not loopback and names the call site that made it. Wired
// per package because each one runs its own vitest;
// packages/eslint-config/test/no-network-runtime.test.js fails the workspace
// if a package drops the entry or points it at the wrong path.
//
// This package serves its fixture release over loopback on purpose, which the
// guard permits and the Linux `No-network` job's namespace does too (it brings
// `lo` up before running the suite). What the guard cannot see is the `sh` /
// `powershell` child this suite spawns — a child process has its own copy of
// node:net — so the assertion that the installers reach nothing but the fixture
// base rests on that CI job, not on this entry.
const noNetworkGuard = fileURLToPath(new URL('../../test/setup/no-network.ts', import.meta.url));

export default defineConfig({
  test: {
    setupFiles: [noNetworkGuard],
    coverage: coverageOptions(import.meta.url),
    environment: 'node',
    // These cases spawn a real shell, build a real archive and extract it. On
    // Windows the one archive that must carry a startable binary packs a copy of
    // the Node executable (the only real PE guaranteed present), so both the zip
    // and the expand are over a hundred MB — well past vitest's 5 s default, and
    // slower again on a contended runner.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
