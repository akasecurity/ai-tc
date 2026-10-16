// Every test file starts with Codex's home pointed at an empty directory and with
// no Codex key, token or gateway address in the environment, stated rather than
// inherited.
//
// `aka status` and `aka enroll --list-detected` read Codex's login file to say why
// the login signed in now does or does not count. Left to its default the read
// goes to `~/.codex`, and `base` redirects `~/.aka` and reaches none of this: a
// test that builds a whole fake machine in a temp dir and names no Codex home
// still reads the REAL developer's login. A key, a token or a gateway address in
// the developer's own environment changes the answer too: the login is read first
// and the environment then vetoes it, so the line says an API key or another
// provider is in use whatever the file holds. The block a case renders then
// depends on whose laptop ran the suite, and assertions that use `toContain` keep
// passing on every other machine.
//
// The location moves through `CODEX_HOME`, the variable the account check already
// honours (`readCodexAccountEnv` in @akasecurity/plugin-sdk), so no product code
// carries a test branch. The directory is created here and stays empty: a login
// file under it is the case's own doing. A case that wants another location says
// so with `codexHome`, or by stubbing the variable, and `vi.unstubAllEnvs()` brings
// it back to this one.
//
// Every other variable the account check reads is set to the empty string, which it
// reads as unset. The names come from `CODEX_ACCOUNT_ENV_NAMES`, a list kept by
// hand: a name added to that list is cleared here too, and the guard test reads
// each back. A test in @akasecurity/plugin-sdk fails when the check reads a name
// that list does not hold.
//
// It reaches as far as THIS PROCESS and no further: a spawned child inherits these
// variables only if the case's env object carries them.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll } from 'vitest';

import { CODEX_ACCOUNT_ENV_NAMES } from '../../packages/plugin-sdk/src/account/account-env.ts';

const CLEARED = CODEX_ACCOUNT_ENV_NAMES.filter((name) => name !== 'CODEX_HOME');

const emptyHome = mkdtempSync(join(tmpdir(), 'aka-empty-codex-home-'));

// eslint-disable-next-line n/no-process-env -- a test guard, not product code: it declares the environment the suite runs in.
const env = process.env;
env.CODEX_HOME = emptyHome;
for (const name of CLEARED) env[name] = '';

afterAll(() => {
  rmSync(emptyHome, { recursive: true, force: true });
});
