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
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// IMPORTED from the resolver rather than re-declared: a local copy of either
// literal would prove the two copies agree and nothing else.
import {
  CONTENT_RETENTION_MARKER_NAME,
  CONTENT_RETENTION_SCRIPT_NAME,
} from '@akasecurity/plugin-runtime';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

const built = (name: string): string => join(SCRIPTS_DIR, name);
const marker = (home: string): string => join(home, '.aka', 'data', CONTENT_RETENTION_MARKER_NAME);

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
    // build itself and could not fail for the reason it appears to check. The
    // entry KEY is what tsup turns into the emitted filename.
    const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
    const key = CONTENT_RETENTION_SCRIPT_NAME.replace(/\.js$/, '');
    expect(
      new RegExp(`(^|\\s)'?${key}'?: '`, 'm').test(config),
      `tsup declares no \`${key}\` entry, so scripts/${CONTENT_RETENTION_SCRIPT_NAME} is never ` +
        'emitted and triggerContentRetention resolves a path that does not exist. The spawn ' +
        'then fails with ENOENT on a later tick, spawnDetached swallows it, and every machine ' +
        'with expiry switched on stops expiring with nothing recording the gap.',
    ).toBe(true);

    expect(existsSync(built(CONTENT_RETENTION_SCRIPT_NAME))).toBe(true);
  });

  it('lands beside the hook that spawns it, since the resolution is by sibling', () => {
    // Not tidiness: the URL resolves against the RUNNING script's directory, so
    // one flat directory is the mechanism rather than a convention.
    expect(existsSync(built('session-start.js'))).toBe(true);
    expect(dirname(built(CONTENT_RETENTION_SCRIPT_NAME))).toBe(dirname(built('session-start.js')));
  });

  it('runs to a clean exit, and creates nothing, on a machine with expiry off', () => {
    // Off is the default and so the overwhelming case, and it is where a crash
    // would be worst: the child is spawned detached with stdio ignored, so a
    // non-zero exit or a stack trace reaches nobody. Creating NO store is part
    // of the property — a feature nobody switched on must not leave a database
    // behind as evidence it considered running.
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

  it('is triggered by a REAL SessionStart once expiry is switched on', () => {
    // The end-to-end half. The marker is written by the throttle probe inside
    // the hook's own process, synchronously, before the detached spawn — so it
    // is the one observable that says "SessionStart reached the trigger and the
    // trigger decided to spawn" without racing a child nobody waits for.
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

  it('is NOT triggered by a SessionStart while expiry is off', () => {
    // The control, and it is what stops the case above passing on a hook that
    // probes the throttle unconditionally. Off by default means a machine that
    // never switched this on must carry no marker — a file appearing there is a
    // feature nobody enabled announcing itself.
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
