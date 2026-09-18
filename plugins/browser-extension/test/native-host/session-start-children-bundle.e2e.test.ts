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
 *
 * A clean exit is the ONLY thing the shared run cases below can tell apart from
 * a no-op that also exits 0 — a bare `process.exit(0);` in place of any of the
 * three built children passes every one of them. `history-sync.js` has no
 * offline observable on a machine that has never attached: it reads a
 * credential that is absent, decides there is nothing to send, and exits —
 * indistinguishable on disk from doing nothing. `content-retention.js` does
 * have one, and the cases below pair it with the off-by-default control so
 * neither reads as a no-op.
 */
import type { SpawnSyncReturns } from 'node:child_process';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { managedSettingsPaths, readManagedSettings } from '@akasecurity/persistence';
import * as pluginRuntime from '@akasecurity/plugin-runtime';
import {
  CONTENT_RETENTION_SCRIPT_NAME,
  HISTORY_SYNC_SCRIPT_NAME,
  SYNC_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import type { TestContext } from 'vitest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import tsupConfig from '../../tsup.config.ts';

// test/native-host -> plugins/browser-extension
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOST_DIR = join(PACKAGE_ROOT, 'native-host');

// spawnSync cannot be interrupted, so a hung child blocks the full deadline and
// vitest then reports a bare per-test timeout — losing the run.error/stderr
// diagnostics the assertions below exist to surface. Kept well under the
// package's 20s testTimeout so a real failure stays readable.
const RUN_TIMEOUT_MS = 10_000;

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

/**
 * The `bodyRetention` this machine's administrator pins, if any — which is
 * what the built child applies inside its own process, whatever settings.json
 * says.
 *
 * Read by EXPLICIT path. The no-managed-settings setup file moves only the
 * default, so a bare `readManagedSettings()` here would report an unmanaged
 * machine rather than the one the child actually runs on.
 */
const machinePin = readManagedSettings(managedSettingsPaths())?.values.bodyRetention;

/** Skip a case whose written `enabled` this machine's administrator overrides. */
function skipIfPinnedOtherwise(ctx: TestContext, writtenEnabled: boolean): void {
  if (machinePin !== undefined && machinePin.enabled !== writtenEnabled) {
    ctx.skip(
      `this machine's managed settings pin bodyRetention.enabled=${String(machinePin.enabled)}, ` +
        'and the built child applies that file in its own process, so it cannot observe what ' +
        'this case writes',
    );
  }
}

/** Write settings.json directly — the child reads it off disk. */
function writeBodyRetentionSettings(home: string, bodyRetention: unknown): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ specVersion: 8, runMode: 'standalone', bodyRetention }),
  );
}

/** Run a built child from the copied bundle against a throwaway home. */
function runChild(name: string, home: string): SpawnSyncReturns<string> {
  // A minimal env: the two variables point os.homedir() at the throwaway home
  // on both platforms, so the run cannot read or write a real ~/.aka.
  return spawnSync(process.execPath, [join(copiedHostDir, name)], {
    encoding: 'utf8',
    env: { HOME: home, USERPROFILE: home },
    timeout: RUN_TIMEOUT_MS,
  });
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
      const run = runChild(name, home);

      expect(run.error).toBeUndefined();
      expect(run.status, `stderr: ${run.stderr}`).toBe(0);
      // Spawned detached with stdio ignored, so anything printed reaches nobody.
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    },
  );

  // content-retention.js is the one built child with an offline observable
  // beyond its exit code: it opens the local store only once expiry is
  // switched on. Paired so neither case alone reads as a no-op — the off case
  // above already covers a clean exit; what it does not cover is that a bare
  // `process.exit(0);` in its place would pass identically.
  it('content-retention.js opens no store on a machine with expiry off', (ctx) => {
    // No settings file is written, so the child reads the default: off. A pin
    // of `enabled: true` makes it open the store, which this case cannot
    // observe.
    skipIfPinnedOtherwise(ctx, false);
    const home = mkdtempSync(join(tmpdir(), 'aka-ext-content-retention-off-'));
    temps.push(home);
    const run = runChild(CONTENT_RETENTION_SCRIPT_NAME, home);

    expect(run.error).toBeUndefined();
    expect(run.status, `stderr: ${run.stderr}`).toBe(0);
    expect(existsSync(join(home, '.aka', 'data', 'aka.db'))).toBe(false);
  });

  it('content-retention.js opens the store on a machine with expiry on', (ctx) => {
    skipIfPinnedOtherwise(ctx, true);
    const home = mkdtempSync(join(tmpdir(), 'aka-ext-content-retention-on-'));
    temps.push(home);
    writeBodyRetentionSettings(home, { enabled: true, retainDays: 30 });
    const run = runChild(CONTENT_RETENTION_SCRIPT_NAME, home);

    expect(run.error).toBeUndefined();
    expect(run.status, `stderr: ${run.stderr}`).toBe(0);
    expect(
      existsSync(join(home, '.aka', 'data', 'aka.db')),
      'content-retention.js opened no store, so a no-op in its place would have passed identically',
    ).toBe(true);
  });
});
