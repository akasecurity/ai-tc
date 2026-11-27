// Every test file starts with an empty home directory and no Codex system
// configuration, stated rather than inherited.
//
// The Codex provider resolution reads `config.toml` from the Codex home, which
// defaults to `~/.codex`, and from `/etc/codex/config.toml` underneath it. A
// case that unsets `CODEX_HOME` would otherwise read the developer's own files,
// and a home whose configuration selects Azure or a gateway vetoes every Codex
// account check. `HOME` and `USERPROFILE` point at an empty temporary directory,
// which `os.homedir()` returns, and the system layer points at a file inside it
// that does not exist.
//
// The seam is imported from its one module by relative path, so the setup file
// caches no other module before a suite registers its mocks.
//
// It reaches as far as THIS PROCESS: a spawned child inherits the home only if
// the case's env object carries it.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll } from 'vitest';

import { UNSAFE_TEST_ONLY_setCodexSystemConfigPath } from '../../packages/plugin-sdk/src/codex-config.ts';

const emptyHome = mkdtempSync(join(tmpdir(), 'aka-empty-home-'));

// eslint-disable-next-line n/no-process-env -- a test guard, not product code: it declares the environment the suite runs in.
const env = process.env;
env.HOME = emptyHome;
env.USERPROFILE = emptyHome;
UNSAFE_TEST_ONLY_setCodexSystemConfigPath(join(emptyHome, 'no-system-codex-config.toml'));

afterAll(() => {
  rmSync(emptyHome, { recursive: true, force: true });
});
