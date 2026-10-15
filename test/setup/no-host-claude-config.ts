// Every test file starts with Claude Code's config pointed at an empty directory,
// stated rather than inherited.
//
// `aka status` and `aka enroll --list-detected` read Claude Code's login file to
// say why the login signed in now does or does not count. Left to its default
// the read goes to `~/.claude.json`, and `base` redirects `~/.aka` and reaches
// none of this: a test that builds a whole fake machine in a temp dir and names
// no Claude home still reads the REAL developer's login, so the block it renders
// depends on who ran the suite. Assertions that use `toContain` keep passing on
// every machine and hide it; the ones that would show it fail only on the
// laptop that has a login.
//
// A per-call override cannot close it. A case that passes its own `claudePaths`
// is hermetic, and every case that drives a status read should; but the read
// that fails sits behind a command a test calls without knowing it reaches the
// login file at all, so the declaration is process-scoped, like the property it
// describes, and installed here for the same reason the managed-settings guard
// is: a guarantee that has to hold in every frame belongs in setup, not at a call
// site somebody has to remember.
//
// The location is moved through `CLAUDE_CONFIG_DIR`, the variable the account
// check already honours (`readClaudeAccountEnv` in @akasecurity/plugin-sdk), so
// no production code carries a test branch. The directory is created here and
// stays empty: a login file or a settings layer under it is the case's own doing.
// A case that wants another location says so with `claudePaths`, or by stubbing
// the variable, and `vi.unstubAllEnvs()` brings it back to this one.
//
// It reaches as far as THIS PROCESS and no further, the boundary the other
// guards have: a spawned child inherits the variable only if the case's env
// object carries it, and a built script run under a redirected `HOME` reads that
// home.
//
// It moves the DEFAULT only. The managed settings file Claude Code reads from an
// absolute system path is not moved; `claudePaths.managedSettings` is how a case
// names another one.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll } from 'vitest';

const emptyConfigDir = mkdtempSync(join(tmpdir(), 'aka-empty-claude-config-'));

// eslint-disable-next-line n/no-process-env -- a test guard, not product code: it declares the environment the suite runs in.
process.env.CLAUDE_CONFIG_DIR = emptyConfigDir;

afterAll(() => {
  rmSync(emptyConfigDir, { recursive: true, force: true });
});
