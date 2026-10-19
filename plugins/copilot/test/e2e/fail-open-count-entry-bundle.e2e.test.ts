/**
 * The fail-open counting child has to be reachable from the PUBLISHED plugin,
 * and what it writes has to reach `aka status`.
 *
 * `runHookFailOpen` starts the child as a SIBLING of the running hook script,
 * resolved against `import.meta.url`. Under vitest that is the module's SOURCE
 * path, where no such sibling exists, so the wrapper's own suite injects its
 * counter and nothing there reaches the real resolution. Drop or rename the tsup
 * entry and every other suite stays green while no fail-open is ever counted:
 * the spawn fails on a later tick and its `error` handler swallows it, as
 * designed.
 *
 * A built hook cannot be driven into the wrapper's fail-open branch from outside
 * — every handler answers hostile stdin and a broken store with a declined
 * decision rather than a throw, as the built-hook fail-open suite records — so
 * this pins the halves that chain rests on: the child is emitted beside every
 * hook under the name the wrapper resolves, the built child counts, and the
 * count it leaves is what the status block renders as its `hooks` line.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { dataDir as dataDirOf, settingsDir as settingsDirOf } from '@akasecurity/persistence';
import { renderAttachedStatus } from '@akasecurity/plugin-runtime';
import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

// Imported from the wrapper rather than re-declared: a local copy of the name
// would prove the two copies agree and nothing else.
import { FAIL_OPEN_COUNT_SCRIPT_NAME as CHILD_SCRIPT } from '../../src/hooks/shared.ts';
import tsupConfig from '../../tsup.config.ts';
import { withTempHome } from '../helpers/run-hook.ts';

// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const built = (name: string): string => join(SCRIPTS_DIR, name);

/** Every hook `hooks.json` registers, each of which runs `runHookFailOpen`. */
const HOOKS = ['pre-tool-use', 'session-start', 'user-prompt-submit', 'post-tool-use'];

/**
 * The tsup entry keys, read from the EVALUATED config. `globalSetup` rebuilds
 * `scripts/` before every run, so an `existsSync` alone is restored by the
 * build itself; and a regex over the config's text matches a commented-out
 * entry as readily as a real one.
 */
function declaredEntryKeys(): string[] {
  const config: unknown = tsupConfig;
  if (typeof config !== 'object' || config === null || Array.isArray(config)) {
    throw new Error('tsup.config.ts no longer exports a single options object');
  }
  const { entry } = config as { entry?: unknown };
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new Error('tsup.config.ts no longer declares its entries as a named map');
  }
  return Object.keys(entry);
}

/** Run the built child once, the way the wrapper starts it, under `home`. */
function runChild(home: string) {
  return spawnSync(process.execPath, [built(CHILD_SCRIPT)], {
    env: { HOME: home, USERPROFILE: home },
    encoding: 'utf8',
    timeout: 15_000,
  });
}

describe('the built fail-open counting child', () => {
  it('is DECLARED under the name the wrapper resolves', () => {
    const entries = declaredEntryKeys();
    expect(entries).toContain('pre-tool-use');
    expect(entries).toContain(CHILD_SCRIPT.replace(/\.js$/, ''));

    expect(existsSync(built(CHILD_SCRIPT))).toBe(true);
  });

  it('lands beside every hook that starts it, since the resolution is by sibling', () => {
    for (const hook of HOOKS) {
      expect(declaredEntryKeys(), hook).toContain(hook);
      expect(existsSync(built(`${hook}.js`)), hook).toBe(true);
      expect(dirname(built(CHILD_SCRIPT))).toBe(dirname(built(`${hook}.js`)));
    }
  });

  it('counts one fail-open per run under the home it inherits, silently', () => {
    withTempHome((home) => {
      const before = Date.now();
      const first = runChild(home);
      const second = runChild(home);
      const after = Date.now();

      for (const run of [first, second]) {
        expect(run.status, run.stderr).toBe(0);
        expect(run.stdout).toBe('');
        expect(run.stderr).toBe('');
      }
      const tally = readHookFailOpens(join(home, '.aka', 'data'));
      expect(tally?.failOpens).toBe(2);
      expect(tally?.lastAtMs).toBeGreaterThanOrEqual(before);
      expect(tally?.lastAtMs).toBeLessThanOrEqual(after);
    }, 'aka-copilot-fail-open-count-');
  });

  it('leaves a count `aka status` renders as its hooks line', () => {
    withTempHome((home) => {
      const base = join(home, '.aka');
      const status = (): string =>
        renderAttachedStatus({
          base,
          settingsDir: settingsDirOf(base),
          dataDir: dataDirOf(base),
        });
      // The control: a machine whose hooks never failed open shows no line, so
      // the line below is the child's doing rather than the block's default.
      expect(status()).not.toContain('failed open');

      expect(runChild(home).status).toBe(0);
      expect(status()).toContain('hooks      failed open at least 1 time(s)');
    }, 'aka-copilot-fail-open-count-status-');
  });

  it('still exits 0, silently, where the home cannot hold a tally', () => {
    withTempHome((home) => {
      // A file where the ~/.aka directory belongs, so nothing under it can be made.
      writeFileSync(join(home, '.aka'), '');
      const run = runChild(home);

      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    }, 'aka-copilot-fail-open-count-blocked-');
  });
});
