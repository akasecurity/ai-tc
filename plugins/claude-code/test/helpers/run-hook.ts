/**
 * Spawns a hook's BUILT script (scripts/<name>.js) exactly as Claude Code
 * invokes it — the only layer that tests what ships, not the source. Hook
 * entries call main() on import and exit the process, so they can never be
 * imported directly by a test; spawning the compiled artifact is the only
 * way to exercise them.
 *
 * `stdin` is a raw string (or Buffer), not a JS value the helper serializes —
 * the fail-open matrix this harness exists for (malformed JSON, truncated
 * JSON, binary garbage) requires feeding a hook exactly that kind of invalid
 * payload, which a helper that only accepted JSON-serializable input could
 * never produce. Callers who want valid input build it themselves, e.g.
 * `runHook('session-start', JSON.stringify({ session_id: 'x' }))`.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/helpers -> plugins/claude-code
const PLUGIN_ROOT = join(HERE, '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

export interface HookResult {
  status: number;
  stdout: string;
  stderr: string;
}

export interface RunHookOptions {
  /** argv passed after the script path (e.g. the plugin manifest path). */
  args?: readonly string[];
  /** Extra env vars layered on top of the inherited process env. */
  env?: Readonly<Record<string, string>>;
  timeoutMs?: number;
}

// The host env, read once so spawned scripts inherit PATH/node — the one
// sanctioned reason to touch it here (mirrors test/journey/harness.ts).
// eslint-disable-next-line n/no-process-env -- test harness needs host PATH to spawn the real scripts
const HOST_ENV = process.env;

// Spawns the built scripts/<name>.js exactly as Claude Code invokes it: raw
// stdin in, exit code + stdout/stderr out. `scripts/` is gitignored and only
// produced by `pnpm run build` — fail with a clear message rather than a
// confusing ENOENT if a caller runs this without building first (in normal
// use this package's vitest.config.ts globalSetup already builds before any
// test file runs, so this is a defensive fallback, not the primary guard).
export function runHook(name: string, stdin: string, options: RunHookOptions = {}): HookResult {
  const scriptPath = join(SCRIPTS_DIR, `${name}.js`);
  if (!existsSync(scriptPath)) {
    throw new Error(
      `runHook('${name}'): ${scriptPath} does not exist. scripts/ is gitignored and only ` +
        'produced by `pnpm run build` (plugins/claude-code) — build the plugin before running this test.',
    );
  }

  // spawnSync rather than execFileSync: execFileSync returns stdout ALONE and
  // lets the child's stderr through to the parent, so a hook that exits 0 while
  // writing a warning read as having written nothing. Every absence assertion
  // over `stderr` on a success path was therefore vacuous, and the once-per-
  // session store-redirect warning could not be asserted at all. spawnSync
  // captures both streams on every path and never throws on a non-zero exit.
  const result = spawnSync(process.execPath, [scriptPath, ...(options.args ?? [])], {
    input: stdin,
    encoding: 'utf8',
    timeout: options.timeoutMs ?? 15_000,
    env: { ...HOST_ENV, ...options.env },
    maxBuffer: 64 * 1024 * 1024,
  });
  // `encoding` types both streams as string, but a child that never STARTED
  // fills neither, so the runtime shape is wider than the declared one.
  const { error, status, stdout, stderr } = result as unknown as {
    error?: Error;
    status: number | null;
    stdout: string | null;
    stderr: string | null;
  };
  // A timeout or a maxBuffer overrun sets `error` while still carrying
  // everything captured before the kill — surface it, the way the execFileSync
  // catch this replaced did, so a test asserts against the hook's real partial
  // output instead of ''. Only a child that produced NOTHING reports the error
  // text itself, which is the absent-hook case.
  if (error && stdout === null && stderr === null) {
    return { status: 1, stdout: '', stderr: error.message };
  }
  // A killed or timed-out child reports status null with a signal; treat that as
  // a failure rather than as a silent 0, which is what `?? 1` is doing here.
  return { status: status ?? 1, stdout: stdout ?? '', stderr: stderr ?? '' };
}

// An isolated ~/.aka + ~/.claude for one runHook() call: os.homedir() — which
// every hook resolves its data dir and transcript store through — honors
// $HOME on POSIX, so overriding it points the whole chain at a throwaway temp
// home instead of a developer's real store (same technique as
// test/journey/harness.ts). Windows resolves the home dir from USERPROFILE
// instead of HOME, so both are set in lockstep.
//
// `prefix` defaults to a generic tag; pass a case-specific one (e.g.
// `aka-ups-redact-`) so a directory a failed teardown leaves behind on disk
// still names the case that leaked it.
export function withTempHome<T>(fn: (home: string) => T, prefix = 'aka-hook-e2e-'): T {
  const home = mkdtempSync(join(tmpdir(), prefix));
  try {
    return fn(home);
  } finally {
    removeTree(home);
  }
}

// Convenience: temp-home env vars for RunHookOptions.env, so a caller can
// write `runHook(name, stdin, { env: tempHomeEnv(home) })` instead of
// repeating the HOME/USERPROFILE pair at every call site.
export function tempHomeEnv(home: string): Record<string, string> {
  return { HOME: home, USERPROFILE: home };
}
