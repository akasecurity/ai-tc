// Every test file starts with Codex's home pointed at an empty directory and with
// no Codex key, token or gateway address in the environment, stated rather than
// inherited.
//
// `aka status` and `aka enroll --list-detected` read Codex's login file to say why
// the login signed in now does or does not count. Left to its default the read
// goes to `~/.codex`, and `base` redirects `~/.aka` and reaches none of this: a
// test that builds a whole fake machine in a temp dir and names no Codex home
// still reads the REAL developer's login. A key, a token or a gateway address in
// the developer's own environment changes the answer too, because it vetoes the
// login before the file says anything. The block a case renders then depends on
// whose laptop ran the suite, and assertions that use `toContain` keep passing on
// every other machine.
//
// The location moves through `CODEX_HOME`, the variable the account check already
// honours (`readCodexAccountEnv` in @akasecurity/plugin-sdk), so no product code
// carries a test branch. The directory is created here and stays empty: a login
// file under it is the case's own doing. A case that wants another location says
// so with `codexHome`, or by stubbing the variable, and `vi.unstubAllEnvs()` brings
// it back to this one.
//
// It reaches as far as THIS PROCESS and no further: a spawned child inherits these
// variables only if the case's env object carries them.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll } from 'vitest';

/** The variables, besides the home, whose presence changes what a Codex login check answers. */
const CLEARED = ['CODEX_API_KEY', 'CODEX_ACCESS_TOKEN', 'OPENAI_BASE_URL'] as const;

const emptyHome = mkdtempSync(join(tmpdir(), 'aka-empty-codex-home-'));

// eslint-disable-next-line n/no-process-env -- a test guard, not product code: it declares the environment the suite runs in.
const env = process.env;
env.CODEX_HOME = emptyHome;
for (const name of CLEARED) env[name] = '';

afterAll(() => {
  rmSync(emptyHome, { recursive: true, force: true });
});
