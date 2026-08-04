/**
 * Spawns a hook's BUILT script (scripts/<name>.js) exactly as Codex invokes it
 * — the only layer that tests what ships, not the source. Hook entries call
 * main() on import and exit the process, so they can never be imported directly
 * by a test; spawning the compiled artifact is the only way to exercise them.
 *
 * `stdin` is a raw string, not a JS value the helper serializes — the fail-open
 * matrix this harness exists for (malformed JSON, truncated JSON, binary
 * garbage) requires feeding a hook exactly that kind of invalid payload, which
 * a helper that only accepted JSON-serializable input could never produce.
 * Callers who want valid input build it themselves, e.g.
 * `runHook('session-start', JSON.stringify({ session_id: 'x' }))`.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/helpers -> plugins/codex
const PLUGIN_ROOT = join(HERE, '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

export interface HookResult {
  status: number;
  stdout: string;
  stderr: string;
}

export interface RunHookOptions {
  /** argv passed after the script path. */
  args?: readonly string[];
  /** The child's entire environment. */
  env?: Readonly<Record<string, string>>;
  timeoutMs?: number;
}

// Spawns the built scripts/<name>.js exactly as Codex invokes it: raw stdin in,
// exit code + stdout/stderr out. `scripts/` is gitignored and only produced by
// `pnpm run build` — fail with a clear message rather than a confusing ENOENT
// if a caller runs this without building first (in normal use this package's
// vitest.config.ts globalSetup already builds before any test file runs, so
// this is a defensive fallback, not the primary guard).
//
// The child gets ONLY the env the caller passes — process.execPath is an
// absolute node path, so nothing here needs the host PATH, and inheriting no
// ambient environment keeps a developer's real CODEX_HOME or provider
// credentials out of the spawn. Same choice as this package's per-suite
// harnesses.
export function runHook(name: string, stdin: string, options: RunHookOptions = {}): HookResult {
  const scriptPath = join(SCRIPTS_DIR, `${name}.js`);
  if (!existsSync(scriptPath)) {
    throw new Error(
      `runHook('${name}'): ${scriptPath} does not exist. scripts/ is gitignored and only ` +
        'produced by `pnpm run build` (plugins/codex) — build the plugin before running this test.',
    );
  }

  try {
    const stdout = execFileSync(process.execPath, [scriptPath, ...(options.args ?? [])], {
      input: stdin,
      encoding: 'utf8',
      timeout: options.timeoutMs ?? 15_000,
      env: { ...options.env },
      maxBuffer: 64 * 1024 * 1024,
    });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    // A non-zero exit (or a killed/timed-out process) still carries the
    // captured streams; surface them so a test can assert against the real
    // output instead of a bare throw.
    const e = err as { stdout?: string; stderr?: string; status?: number | null };
    return {
      status: e.status ?? 1,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

// An isolated ~/.aka for one runHook() call: os.homedir() — which every hook
// resolves its data dir through — honors $HOME on POSIX, so overriding it
// points the whole chain at a throwaway temp home instead of a developer's real
// store. Windows resolves the home dir from USERPROFILE instead of HOME, so
// both are set in lockstep.
export function withTempHome<T>(fn: (home: string) => T): T {
  const home = mkdtempSync(join(tmpdir(), 'aka-codex-hook-e2e-'));
  try {
    return fn(home);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// Convenience: temp-home env vars for RunHookOptions.env, so a caller can
// write `runHook(name, stdin, { env: tempHomeEnv(home) })` instead of
// repeating the HOME/USERPROFILE pair at every call site.
export function tempHomeEnv(home: string): Record<string, string> {
  return { HOME: home, USERPROFILE: home };
}
