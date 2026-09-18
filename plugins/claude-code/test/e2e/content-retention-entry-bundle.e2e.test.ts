/**
 * The body-expiry child has to be reachable from the PUBLISHED plugin, and the
 * trigger that reaches it has to fire from the REAL SessionStart hook.
 *
 * `triggerContentRetention` resolves `content-retention.js` as a SIBLING of the
 * running script (`new URL(..., import.meta.url)`), the way both attached-mode
 * children do, and it inherits their trap: under vitest `import.meta.url` is the
 * module's SOURCE path, so the sibling does not exist there, and every case in
 * the trigger's own suite injects `scriptUrl` or `spawnChild`. Nothing in it
 * exercises the real resolution.
 *
 * The drift is silent by construction. Rename or drop the `content-retention`
 * tsup entry, or emit it somewhere other than `scripts/`, and the whole suite
 * stays green while every machine with expiry switched on stops expiring: the
 * spawn's ENOENT arrives on a later tick and `spawnDetached`'s `error` handler
 * swallows it, as designed. The store then grows for ever with nothing anywhere
 * recording that the sweep never ran.
 *
 * The LAST TWO CASES are the half no other suite reaches. The trigger's unit
 * tests prove what it decides when called; this proves SessionStart calls it —
 * against the built hook, on a real temp home, with the setting read off disk
 * rather than handed in.
 *
 * Three cases sit on the far side of the managed-settings boundary: those two,
 * and the one before them that runs the child directly with no settings file.
 * `bodyRetention` is a key an administrator may pin, and every built script
 * applies the machine's managed file inside ITS OWN process, from absolute
 * system paths a redirected home does not move. This suite's
 * no-managed-settings setup file lives in the vitest process and never reaches
 * that child. So on a machine whose administrator pins an `enabled` that
 * disagrees with what a case writes (no settings file reads as the default,
 * off), the script obeys the pin and the case would be reporting the machine
 * rather than the code. Each of the three reads that file itself and skips when
 * it disagrees. CI carries no managed file, so there all three always run.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { managedSettingsPaths, readManagedSettings } from '@akasecurity/persistence';
// IMPORTED from the resolver rather than re-declared: a local copy of either
// literal would prove the two copies agree and nothing else.
import {
  CONTENT_RETENTION_MARKER_NAME,
  CONTENT_RETENTION_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import type { TestContext } from 'vitest';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';
import { declaredEntryKeys } from '../helpers/tsup-entries.ts';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

const built = (name: string): string => join(SCRIPTS_DIR, name);
const marker = (home: string): string => join(home, '.aka', 'data', CONTENT_RETENTION_MARKER_NAME);

/**
 * The `bodyRetention` this machine's administrator pins, if any — which is what
 * the built hook acts on, whatever settings.json says. A pin replaces the user's
 * value on every read, locked or not.
 *
 * Read by EXPLICIT path. The no-managed-settings setup file moves only the
 * default, so a bare `readManagedSettings()` here would report that pin — an
 * unmanaged machine — rather than the machine the child actually runs on.
 */
const machinePin = readManagedSettings(managedSettingsPaths())?.values.bodyRetention;

/** Skip a case whose written `enabled` this machine's administrator overrides. */
function skipIfPinnedOtherwise(ctx: TestContext, writtenEnabled: boolean): void {
  if (machinePin !== undefined && machinePin.enabled !== writtenEnabled) {
    ctx.skip(
      `this machine's managed settings pin bodyRetention.enabled=${String(machinePin.enabled)}, ` +
        'and the built hook applies that file in its own process, so it cannot observe what ' +
        'this case writes',
    );
  }
}

/** Write settings.json directly — the child and the hook both read it off disk. */
function writeSettings(home: string, bodyRetention: unknown): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ specVersion: 8, runMode: 'standalone', bodyRetention }),
  );
}

function sessionStartPayload(home: string): string {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return JSON.stringify({
    session_id: 'content-retention-e2e',
    cwd,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
}

describe('the built body-expiry child', () => {
  it('is DECLARED under the name the trigger resolves', () => {
    // Asserted against the tsup CONFIG rather than only the emitted file: the
    // build runs before every suite, so an existsSync alone is restored by the
    // build itself and could not fail for the reason it appears to check.
    //
    // Read from the EVALUATED config rather than the file's text: a regex over
    // the source matches a commented-out entry exactly as readily as a real
    // one, so it cannot tell "removed" from "declared". The entry KEY is what
    // tsup turns into the emitted filename.
    const key = CONTENT_RETENTION_SCRIPT_NAME.replace(/\.js$/, '');
    expect(
      declaredEntryKeys(),
      `tsup declares no \`${key}\` entry, so scripts/${CONTENT_RETENTION_SCRIPT_NAME} is never ` +
        'emitted and triggerContentRetention resolves a path that does not exist. The spawn ' +
        'then fails with ENOENT on a later tick, spawnDetached swallows it, and every machine ' +
        'with expiry switched on stops expiring with nothing recording the gap.',
    ).toContain(key);

    expect(existsSync(built(CONTENT_RETENTION_SCRIPT_NAME))).toBe(true);
  });

  it('lands beside the hook that spawns it, since the resolution is by sibling', () => {
    // Not tidiness: the URL resolves against the RUNNING script's directory, so
    // one flat directory is the mechanism rather than a convention.
    expect(existsSync(built('session-start.js'))).toBe(true);
    expect(dirname(built(CONTENT_RETENTION_SCRIPT_NAME))).toBe(dirname(built('session-start.js')));
  });

  it('runs to a clean exit, and creates nothing, on a machine with expiry off', (ctx) => {
    // Off is the default and so the overwhelming case, and it is where a crash
    // would be worst: the child is spawned detached with stdio ignored, so a
    // non-zero exit or a stack trace reaches nobody. Creating NO store is part
    // of the property — a feature nobody switched on must not leave a database
    // behind as evidence it considered running.
    //
    // No settings file is written, so the child reads the default: off. A pin of
    // `enabled: true` makes it open the store, which this case cannot observe.
    skipIfPinnedOtherwise(ctx, false);
    withTempHome((home) => {
      const run = runHook(CONTENT_RETENTION_SCRIPT_NAME.replace(/\.js$/, ''), '', {
        env: tempHomeEnv(home),
      });

      expect(run.status, `stderr: ${run.stderr}`).toBe(0);
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
      expect(existsSync(join(home, '.aka', 'data', 'aka.db'))).toBe(false);
    });
  });

  it('is triggered by a REAL SessionStart once expiry is switched on', (ctx) => {
    // The end-to-end half. The marker is written by the throttle probe inside
    // the hook's own process, synchronously, before the detached spawn — so it
    // is the one observable that says "SessionStart reached the trigger and the
    // trigger decided to spawn" without racing a child nobody waits for.
    skipIfPinnedOtherwise(ctx, true);
    withTempHome((home) => {
      writeSettings(home, { enabled: true, retainDays: 30 });

      const run = runHook('session-start', sessionStartPayload(home), {
        env: tempHomeEnv(home),
      });
      expect(run.status, `stderr: ${run.stderr}`).toBe(0);

      expect(
        existsSync(marker(home)),
        'SessionStart wrote no throttle marker, so the body-expiry trigger never ran on the ' +
          'real hook path — the unit tests call it directly and cannot see this.',
      ).toBe(true);
    });
  });

  it('is NOT triggered by a SessionStart while expiry is off', (ctx) => {
    // The control, and it is what stops the case above passing on a hook that
    // probes the throttle unconditionally. Off by default means a machine that
    // never switched this on must carry no marker — a file appearing there is a
    // feature nobody enabled announcing itself.
    skipIfPinnedOtherwise(ctx, false);
    withTempHome((home) => {
      writeSettings(home, { enabled: false, retainDays: 30 });

      const run = runHook('session-start', sessionStartPayload(home), {
        env: tempHomeEnv(home),
      });
      expect(run.status, `stderr: ${run.stderr}`).toBe(0);

      expect(existsSync(marker(home))).toBe(false);
    });
  });
});
