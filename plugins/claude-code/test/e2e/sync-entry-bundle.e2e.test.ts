/**
 * The policy-sync child has to be reachable from the PUBLISHED plugin, and that
 * is the one thing source-level tests cannot show.
 *
 * `triggerPolicySync` resolves `sync.js` as a SIBLING of the running script
 * (`new URL('sync.js', import.meta.url)`), exactly as the isolated scan resolves
 * its worker — and it has the same trap, one step worse. Under vitest
 * `import.meta.url` is the module's SOURCE path, so `src/attached/sync.js` does
 * not exist there either; and every case in `sync-trigger.test.ts` injects
 * `scriptUrl` or `spawnChild`, so nothing exercises the real resolution at all.
 *
 * The drift is silent by construction: rename or drop the `sync` tsup entry, or
 * emit it somewhere other than `scripts/`, and the whole suite stays green while
 * attached machines stop pulling policy — the spawn's ENOENT arrives on a later
 * tick and `spawnDetached`'s `error` handler swallows it, as designed. Nothing
 * anywhere records the gap, and status renders "no attempt recorded yet"
 * forever, which reads like a machine that has simply not synced yet.
 *
 * So this drives the BUILT artifact: the emitted script has to exist under the
 * name the resolver probes for, and it has to run.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

// The filename `triggerPolicySync` probes for. tsup's entry key is what
// produces it, so the two have to change together or the child becomes
// unreachable at runtime — which is the whole point of asserting the name here
// rather than trusting the config.
const SYNC_SCRIPT = 'sync.js';

const built = (name: string): string => join(SCRIPTS_DIR, name);

describe('the built policy-sync child', () => {
  it('is DECLARED under the name the trigger resolves', () => {
    // Asserted against the tsup CONFIG rather than against the emitted file,
    // and that distinction is the whole value of this case. `globalSetup`
    // rebuilds `scripts/` before every run, so an `existsSync` here is restored
    // by the build itself and cannot fail for the reason it appears to check —
    // deleting the entry, renaming it, or pointing it at another outDir would
    // all leave a file-existence assertion green.
    //
    // The entry KEY is what tsup turns into the emitted filename, so comparing
    // it against the name the resolver probes for is the check that a rename
    // actually trips.
    const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
    const key = SYNC_SCRIPT.replace(/\.js$/, '');
    expect(
      new RegExp(`(^|\\s)${key}: '`, 'm').test(config),
      `tsup declares no \`${key}\` entry, so scripts/${SYNC_SCRIPT} is never emitted and ` +
        'triggerPolicySync resolves a path that does not exist. The spawn then fails with ' +
        'ENOENT on a later tick, spawnDetached swallows it, and attached machines stop ' +
        'pulling policy with nothing recording the gap.',
    ).toBe(true);

    // And the build really does produce it, which is what makes the run below
    // meaningful rather than a check of a stale artifact.
    expect(existsSync(built(SYNC_SCRIPT))).toBe(true);
  });

  it('lands beside the hook that spawns it, since the resolution is by sibling', () => {
    // Not a tidiness check: `new URL('sync.js', import.meta.url)` resolves
    // against the RUNNING script's directory, so the two being in one flat
    // directory is the mechanism rather than a convention.
    expect(existsSync(built('session-start.js'))).toBe(true);
    expect(dirname(built(SYNC_SCRIPT))).toBe(dirname(built('session-start.js')));
  });

  it('runs to a clean exit on a machine that is not attached', () => {
    // The common case by far, and the one where a crash would be worst: the
    // child is spawned detached with stdio ignored, so a non-zero exit or a
    // stack trace reaches nobody. It must find no attachment and stop.
    const home = mkdtempSync(join(tmpdir(), 'aka-sync-e2e-'));
    try {
      // A MINIMAL env, not an inherited one. The child is `node <script>`, so
      // it needs nothing from this process's environment, and the two variables
      // below are the whole point of the case: they redirect `~/.aka` to a
      // throwaway home so the run cannot read — or write — the developer's own
      // store. Inheriting would also mean touching `process.env`, which the
      // workspace bans outside the sites §3 tables.
      const run = spawnSync(process.execPath, [built(SYNC_SCRIPT)], {
        encoding: 'utf8',
        env: { HOME: home, USERPROFILE: home },
        timeout: 30_000,
      });

      expect(run.status, `stderr: ${run.stderr}`).toBe(0);
      // Nothing on either channel: this process has no reader, so anything it
      // printed would be written to a pipe nobody drains.
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
