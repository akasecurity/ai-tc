/**
 * The history-drain child has to be reachable from the PUBLISHED plugin, and
 * that is the one thing source-level tests cannot show.
 *
 * `triggerHistorySync` resolves `history-sync.js` as a SIBLING of the running
 * script (`new URL(..., import.meta.url)`), exactly as the policy-sync child
 * does, and it has the same trap. Under vitest `import.meta.url` is the module's
 * SOURCE path, so the sibling does not exist there; and every case in the
 * trigger's own suite injects `scriptUrl` or `spawnChild`, so nothing exercises
 * the real resolution at all.
 *
 * The drift is silent by construction: rename or drop the `history-sync` tsup
 * entry, or emit it somewhere other than `scripts/`, and the whole suite stays
 * green while attached machines stop draining their backlog — the spawn's ENOENT
 * arrives on a later tick and `spawnDetached`'s `error` handler swallows it, as
 * designed. Status then shows progress that never moves, which reads like a
 * machine with nothing left to send.
 *
 * So this drives the BUILT artifact: the emitted script has to exist under the
 * name the resolver probes for, and it has to run.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// IMPORTED from the resolver rather than re-declared: a local copy of the
// literal would prove the two copies agree and nothing else.
import { HISTORY_SYNC_SCRIPT_NAME as HISTORY_SCRIPT } from '@akasecurity/plugin-runtime';
import { describe, expect, it } from 'vitest';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

const built = (name: string): string => join(SCRIPTS_DIR, name);

describe('the built history-drain child', () => {
  it('is DECLARED under the name the trigger resolves', () => {
    // Asserted against the tsup CONFIG rather than the emitted file: the build
    // runs before every suite, so an existsSync here is restored by the build
    // itself and could not fail for the reason it appears to check. The entry
    // KEY is what tsup turns into the emitted filename.
    const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
    const key = HISTORY_SCRIPT.replace(/\.js$/, '');
    expect(
      new RegExp(`(^|\\s)'?${key}'?: '`, 'm').test(config),
      `tsup declares no \`${key}\` entry, so scripts/${HISTORY_SCRIPT} is never emitted and ` +
        'triggerHistorySync resolves a path that does not exist. The spawn then fails with ' +
        'ENOENT on a later tick, spawnDetached swallows it, and attached machines never send ' +
        'their recorded history with nothing recording the gap.',
    ).toBe(true);

    expect(existsSync(built(HISTORY_SCRIPT))).toBe(true);
  });

  it('lands beside the hook that spawns it, since the resolution is by sibling', () => {
    // Not tidiness: the URL resolves against the RUNNING script's directory, so
    // one flat directory is the mechanism rather than a convention.
    expect(existsSync(built('session-start.js'))).toBe(true);
    expect(dirname(built(HISTORY_SCRIPT))).toBe(dirname(built('session-start.js')));
  });

  it('runs to a clean exit on a machine that is not attached', () => {
    // The common case by far, and the one where a crash would be worst: the
    // child is spawned detached with stdio ignored, so a non-zero exit or a
    // stack trace reaches nobody. It must find no attachment and stop.
    const home = mkdtempSync(join(tmpdir(), 'aka-history-sync-e2e-'));
    try {
      // A MINIMAL env, not an inherited one: the two variables redirect ~/.aka
      // to a throwaway home so the run cannot read — or write — the developer's
      // own store.
      const run = spawnSync(process.execPath, [built(HISTORY_SCRIPT)], {
        encoding: 'utf8',
        env: { HOME: home, USERPROFILE: home },
        timeout: 30_000,
      });

      expect(run.status, `stderr: ${run.stderr}`).toBe(0);
      // Nothing on either channel: this process has no reader.
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
