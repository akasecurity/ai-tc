/**
 * The three detached children `handleSessionStart` can spawn — the policy-sync,
 * history-drain and body-expiry passes — each have to be reachable from the
 * PUBLISHED plugin, and that is the one thing source-level tests cannot show.
 *
 * Each trigger resolves its child as a SIBLING of the running script
 * (`new URL(<name>, import.meta.url)`), exactly as the isolated scan resolves
 * its worker. From an installed plugin the running script is
 * `scripts/session-start.js`, so a child tsup does not emit into `scripts/` is
 * a path that does not exist. The spawn's ENOENT arrives on a later tick and
 * `spawnDetached` swallows it, and — for the throttled two — the throttle
 * marker was written before the spawn, so the same pass is suppressed until its
 * window lapses. Nothing anywhere records the gap.
 *
 * The required set is DERIVED from plugin-runtime's exports rather than listed
 * here, the way `plugins/browser-extension/test/native-host/
 * session-start-children-bundle.e2e.test.ts` derives its own: each trigger
 * exports the filename it resolves as a `*_SCRIPT_NAME` name, so a trigger
 * added to `handleSessionStart` is required here with no edit to this file.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as pluginRuntime from '@akasecurity/plugin-runtime';
import {
  CONTENT_RETENTION_SCRIPT_NAME,
  HISTORY_SYNC_SCRIPT_NAME,
  SYNC_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import { describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import tsupConfig from '../../tsup.config.ts';

// test/e2e -> plugins/codex
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

const built = (name: string): string => join(SCRIPTS_DIR, name);

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

describe('the detached children handleSessionStart spawns', () => {
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
    // clean scripts/, so a file from an earlier build survives the entry that
    // produced it being dropped.
    expect(
      declaredEntryKeys(),
      `tsup declares no \`${entryKey(name)}\` entry, so scripts/${name} is never emitted and ` +
        'the SessionStart trigger that resolves it spawns a path that does not exist',
    ).toContain(entryKey(name));
  });

  it.each(CHILD_SCRIPTS)(
    'lands beside session-start.js, since resolution is by sibling',
    (name) => {
      // Not tidiness: `new URL(name, import.meta.url)` resolves against the
      // RUNNING script's directory, so one flat directory is the mechanism
      // rather than a convention.
      expect(existsSync(built('session-start.js'))).toBe(true);
      expect(dirname(built(name))).toBe(dirname(built('session-start.js')));
    },
  );

  it.each(CHILD_SCRIPTS)(
    'runs %s to a clean exit, from beside session-start.js, on a machine that is not attached',
    (name) => {
      const home = mkdtempSync(join(tmpdir(), 'aka-codex-session-start-child-'));
      try {
        // A MINIMAL env, not an inherited one: the child is `node <script>`, so
        // it needs nothing from this process's environment, and the two
        // variables below redirect `~/.aka` to a throwaway home so the run
        // cannot read — or write — the developer's own store.
        const run = spawnSync(process.execPath, [built(name)], {
          encoding: 'utf8',
          env: { HOME: home, USERPROFILE: home },
          timeout: 30_000,
        });

        expect(run.status, `stderr: ${run.stderr}`).toBe(0);
        // Spawned detached with stdio ignored, so anything printed reaches
        // nobody.
        expect(run.stdout).toBe('');
        expect(run.stderr).toBe('');
      } finally {
        removeTree(home);
      }
    },
  );
});
