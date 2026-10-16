/**
 * The three detached children sessionStart spawns have to be reachable from
 * the PUBLISHED plugin, and the spawn has to fire from the REAL hook.
 *
 * `triggerPolicySync`, `triggerHistorySync` and `triggerContentRetention` each
 * resolve their script as a SIBLING of the running one (`new URL(name,
 * import.meta.url)`). Under vitest `import.meta.url` is a source path, so no
 * in-process test reaches the real resolution, and a missing sibling fails
 * silently: the spawn's ENOENT arrives on a later tick and the trigger's
 * `error` handler swallows it by design. So this drives the built `scripts/`.
 *
 * The SessionStart cases sit on the far side of the managed-settings boundary:
 * `bodyRetention` is a key an administrator may pin, and the built hook applies
 * the machine's managed file in its own process, which a redirected home does
 * not move. Each reads that file itself and skips where it disagrees with what
 * the case writes. CI carries no managed file, so there every case runs.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { managedSettingsPaths, readManagedSettings } from '@akasecurity/persistence';
// IMPORTED from the resolvers rather than re-declared: a local copy of a
// literal proves the two copies agree and nothing else.
import {
  CONTENT_RETENTION_MARKER_NAME,
  CONTENT_RETENTION_SCRIPT_NAME,
  HISTORY_SYNC_SCRIPT_NAME,
  SYNC_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import type { TestContext } from 'vitest';
import { describe, expect, it } from 'vitest';

import tsupConfig from '../../tsup.config.ts';
import { withTempHome } from '../helpers/run-hook.ts';

// test/e2e -> plugins/copilot
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const MANIFEST = join(PLUGIN_ROOT, 'plugin.json');

const built = (name: string): string => join(SCRIPTS_DIR, name);
const marker = (home: string): string => join(home, '.aka', 'data', CONTENT_RETENTION_MARKER_NAME);

const CHILDREN = [SYNC_SCRIPT_NAME, HISTORY_SYNC_SCRIPT_NAME, CONTENT_RETENTION_SCRIPT_NAME];

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

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Run a built script against a throwaway home, with a minimal environment. */
function run(script: string, home: string, args: string[] = [], input = ''): Run {
  const result = spawnSync(process.execPath, [built(script), ...args], {
    env: { HOME: home, USERPROFILE: home },
    input,
    encoding: 'utf8',
    timeout: 30_000,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** The `bodyRetention` this machine's administrator pins, read by explicit path. */
const machinePin = readManagedSettings(managedSettingsPaths())?.values.bodyRetention;

function skipIfPinnedOtherwise(ctx: TestContext, writtenEnabled: boolean): void {
  if (machinePin !== undefined && machinePin.enabled !== writtenEnabled) {
    ctx.skip(
      `this machine's managed settings pin bodyRetention.enabled=${String(machinePin.enabled)}, ` +
        'and the built hook applies that file in its own process',
    );
  }
}

function writeSettings(home: string, bodyRetention: unknown): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ specVersion: 8, runMode: 'standalone', bodyRetention }),
  );
}

function sessionStart(home: string): Run {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  const payload = { sessionId: 'detached-children-e2e', timestamp: 0, cwd, source: 'new' };
  return run('session-start.js', home, ['sessionStart', MANIFEST], JSON.stringify(payload));
}

describe.each(CHILDREN)('the built %s child', (script) => {
  it('is DECLARED under the name its trigger resolves', () => {
    expect(declaredEntryKeys()).toContain(script.replace(/\.js$/, ''));
    expect(existsSync(built(script))).toBe(true);
  });

  it('lands beside session-start.js, since the resolution is by sibling', () => {
    expect(existsSync(built('session-start.js'))).toBe(true);
    expect(dirname(built(script))).toBe(dirname(built('session-start.js')));
  });

  it('runs to a clean, silent exit on a standalone machine', (ctx) => {
    // No settings file reads as the default: standalone, expiry off. The child
    // is spawned with stdio ignored, so a crash here would reach nobody.
    skipIfPinnedOtherwise(ctx, false);
    withTempHome((home) => {
      const result = run(script, home);
      expect(result.status, `stderr: ${result.stderr}`).toBe(0);
      expect(result.stdout).toBe('');
      expect(result.stderr).toBe('');
    }, `aka-copilot-child-${script}-`);
  });
});

describe('the real sessionStart hook spawns the body-expiry child', () => {
  it('reaches the trigger once expiry is switched on', (ctx) => {
    // The throttle marker is written inside the hook's own process,
    // synchronously, just before the detached spawn — the one observable that
    // says the trigger decided to spawn without racing a child nobody awaits.
    skipIfPinnedOtherwise(ctx, true);
    withTempHome((home) => {
      writeSettings(home, { enabled: true, retainDays: 30 });
      const result = sessionStart(home);
      expect(result.status, `stderr: ${result.stderr}`).toBe(0);
      expect(result.stdout).toBe('');
      expect(existsSync(marker(home))).toBe(true);
    }, 'aka-copilot-child-trigger-on-');
  });

  it('does not reach it while expiry is off', (ctx) => {
    // The control: without it the case above passes on a hook that probes the
    // throttle unconditionally.
    skipIfPinnedOtherwise(ctx, false);
    withTempHome((home) => {
      writeSettings(home, { enabled: false, retainDays: 30 });
      const result = sessionStart(home);
      expect(result.status, `stderr: ${result.stderr}`).toBe(0);
      expect(result.stdout).toBe('');
      expect(existsSync(marker(home))).toBe(false);
    }, 'aka-copilot-child-trigger-off-');
  });
});
