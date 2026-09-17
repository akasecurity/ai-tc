/**
 * The fail-open counting child has to be reachable from the PUBLISHED plugin.
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
 * — no hostile stdin or broken store makes a body throw, as the built-hook
 * fail-open suite records — so this pins the two halves that chain rests on:
 * the child is emitted beside the hooks under the name the wrapper resolves, and
 * the built child counts.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

// Imported from the wrapper rather than re-declared: a local copy of the name
// would prove the two copies agree and nothing else.
import { FAIL_OPEN_COUNT_SCRIPT_NAME as CHILD_SCRIPT } from '../../src/hooks/shared.ts';
import { withTempHome } from '../helpers/run-hook.ts';

// test/e2e -> plugins/antigravity
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const built = (name: string): string => join(SCRIPTS_DIR, name);

/** Every entry name tsup is configured to emit, read from the build config. */
function declaredEntries(): string[] {
  const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
  return [...config.matchAll(/^\s*'?([\w-]+)'?:\s*'src\//gm)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined);
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
    // Asserted against the tsup CONFIG rather than only the emitted file: the
    // build runs before every suite, so an existsSync alone is restored by the
    // build itself and could not fail for the reason it appears to check. The
    // entry name is what tsup turns into the emitted filename.
    const entries = declaredEntries();
    expect(entries).toContain('pre-tool-use');
    expect(entries).toContain(CHILD_SCRIPT.replace(/\.js$/, ''));

    expect(existsSync(built(CHILD_SCRIPT))).toBe(true);
  });

  it('lands beside every hook that starts it, since the resolution is by sibling', () => {
    for (const hook of ['pre-invocation', 'pre-tool-use', 'post-tool-use', 'stop']) {
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
    }, 'aka-agy-fail-open-count-');
  });

  it('still exits 0, silently, where the home cannot hold a tally', () => {
    withTempHome((home) => {
      // A file where the ~/.aka directory belongs, so nothing under it can be made.
      writeFileSync(join(home, '.aka'), '');
      const run = runChild(home);

      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    }, 'aka-agy-fail-open-count-blocked-');
  });
});
