/**
 * Every detached child SessionStart spawns has to be emitted beside the native
 * host, and that is the one thing source-level tests cannot show.
 *
 * The host answers a `session_start` message with `handleSessionStart`, the
 * same pass every other harness runs, and each trigger in it resolves its
 * child as a SIBLING of the running bundle (`new URL(<name>, import.meta.url)`)
 * before spawning `process.execPath <script>`. From an installed extension the
 * running bundle is `native-host/host.js`, so a child tsup does not emit into
 * `native-host/` is a path that does not exist. The spawn's ENOENT arrives on
 * a later tick and `spawnDetached` swallows it, and the trigger's throttle
 * marker was written before the spawn — into the data dir every harness on the
 * machine shares — so the same pass is suppressed for all of them until its
 * window lapses.
 *
 * The required set is DERIVED from plugin-runtime's exports rather than listed
 * here: each trigger exports the filename it resolves as a `*_SCRIPT_NAME`, so
 * a trigger added to that pass is required here with no edit to this file.
 */
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as pluginRuntime from '@akasecurity/plugin-runtime';
import {
  CONTENT_RETENTION_SCRIPT_NAME,
  HISTORY_SYNC_SCRIPT_NAME,
  SYNC_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import tsupConfig from '../../tsup.config.ts';

// test/native-host -> plugins/browser-extension
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOST_DIR = join(PACKAGE_ROOT, 'native-host');

/** Every filename plugin-runtime exports under a `*_SCRIPT_NAME` name, sorted. */
const CHILD_SCRIPTS: readonly string[] = Object.entries(pluginRuntime)
  .filter(([name, value]) => name.endsWith('_SCRIPT_NAME') && typeof value === 'string')
  .map(([, value]) => value as string)
  .sort();

/** The tsup entry key that emits `name`: tsup names each output after its key. */
const entryKey = (name: string): string => name.replace(/\.js$/, '');

/**
 * The entry keys of the EVALUATED tsup config. Read from the module rather
 * than its text, because a text match also accepts an entry that has been
 * commented out.
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

const temps: string[] = [];
let copiedHostDir = '';

beforeAll(() => {
  // A copy with no node_modules anywhere above it, so a clean run is a test
  // of the bundle's self-containment rather than of the repo.
  const dir = mkdtempSync(join(tmpdir(), 'aka-ext-children-'));
  temps.push(dir);
  copiedHostDir = join(dir, 'native-host');
  cpSync(HOST_DIR, copiedHostDir, { recursive: true });
});

afterAll(() => {
  removeTrees(temps);
});

describe('the detached children SessionStart spawns from the native host', () => {
  it('are derived from plugin-runtime, and the derivation finds every known trigger', () => {
    // Without this, a rename of the export convention derives an empty set,
    // `it.each` below generates no cases, and the suite reports green.
    expect(CHILD_SCRIPTS).toEqual(
      expect.arrayContaining([
        SYNC_SCRIPT_NAME,
        HISTORY_SYNC_SCRIPT_NAME,
        CONTENT_RETENTION_SCRIPT_NAME,
      ]),
    );
    for (const name of CHILD_SCRIPTS) expect(name).toMatch(/^[a-z][a-z-]*\.js$/);
  });

  it.each(CHILD_SCRIPTS)('declares %s as a tsup entry', (name) => {
    // Asserted against the config rather than the emitted file: tsup does not
    // clean native-host/, so a file from an earlier build survives the entry
    // that produced it being dropped.
    expect(
      declaredEntryKeys(),
      `tsup declares no \`${entryKey(name)}\` entry, so native-host/${name} is never emitted ` +
        'and the SessionStart trigger that resolves it spawns a path that does not exist',
    ).toContain(entryKey(name));
  });

  it.each(CHILD_SCRIPTS)(
    'runs %s to a clean exit, from beside host.js, on a machine that is not attached',
    (name) => {
      const home = mkdtempSync(join(tmpdir(), 'aka-ext-child-home-'));
      temps.push(home);
      // A minimal env: the two variables point os.homedir() at the throwaway
      // home on both platforms, so the run cannot read or write a real ~/.aka.
      const run = spawnSync(process.execPath, [join(copiedHostDir, name)], {
        encoding: 'utf8',
        env: { HOME: home, USERPROFILE: home },
        timeout: 30_000,
      });

      expect(run.error).toBeUndefined();
      expect(run.status, `stderr: ${run.stderr}`).toBe(0);
      // Spawned detached with stdio ignored, so anything printed reaches nobody.
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    },
  );
});
