/**
 * Spawns one BUILT hook script the way the host does — a fresh `node` process
 * fed one JSON payload on stdin — and reports what that process cost.
 *
 * Wall time is taken around the spawn. CPU time is the child's own
 * `process.cpuUsage()` (user + system, every thread of the process) read at
 * its `exit` event by a preload module and written to an extra pipe, so it is
 * measured the same way on every platform and never mixes in this process's
 * own work. The baseline variant runs the same preload over `-e 0`, which is
 * what makes "the hook's cost over a bare node start" a subtraction of two
 * like-for-like readings.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';

import { hostPath } from '../test/helpers/run-hook.ts';

/** A preload that reports the process's CPU time on fd 3 as it exits. */
const CPU_PRELOAD =
  'data:text/javascript,' +
  encodeURIComponent(
    "import { writeSync } from 'node:fs';" +
      "process.on('exit', () => { const u = process.cpuUsage();" +
      ' try { writeSync(3, JSON.stringify(u)); } catch {} });',
  );

export interface HookSample {
  wallMs: number;
  cpuMs: number;
  status: number | null;
  stdout: string;
}

export interface HookRun {
  /** The script to run, or undefined for the bare `node -e 0` baseline. */
  script: string | undefined;
  /** The JSON payload written to stdin. */
  payload: string;
}

/**
 * A disposable home directory, so the hooks read and write a store of their
 * own rather than the developer's. The child receives `HOME`, `USERPROFILE`
 * and `PATH` and nothing else: a hand-built environment keeps the measurement
 * independent of the shell it was started from, and `PATH` is passed through
 * so a child process a hook starts can still be found.
 */
export function createBenchHome(): { env: Record<string, string>; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), 'aka-hook-bench-'));
  const path = hostPath();
  return {
    env: { HOME: home, USERPROFILE: home, ...(path === undefined ? {} : { PATH: path }) },
    cleanup: () => {
      rmSync(home, { recursive: true, force: true });
    },
  };
}

export function runHook(run: HookRun, env: Record<string, string>): HookSample {
  const args =
    run.script === undefined
      ? ['--import', CPU_PRELOAD, '-e', '0']
      : ['--import', CPU_PRELOAD, run.script];
  const started = performance.now();
  const result = spawnSync(process.execPath, args, {
    input: run.payload,
    env,
    stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: 30_000,
  });
  const wallMs = performance.now() - started;
  const cpuRaw = result.output[3];
  const cpu = typeof cpuRaw === 'string' && cpuRaw !== '' ? (JSON.parse(cpuRaw) as unknown) : null;
  if (
    typeof cpu !== 'object' ||
    cpu === null ||
    typeof (cpu as { user?: unknown }).user !== 'number' ||
    typeof (cpu as { system?: unknown }).system !== 'number'
  ) {
    throw new Error(
      `no CPU reading from ${run.script ?? 'the baseline'} (status ${String(result.status)}): ` +
        result.stderr.slice(0, 500),
    );
  }
  const { user, system } = cpu as { user: number; system: number };
  return { wallMs, cpuMs: (user + system) / 1000, status: result.status, stdout: result.stdout };
}

// A bundled rule, read from its own file in the repository's rules/ so this
// module runs under plain node as well as under vitest.
const CONTROL_RULE_FILE = new URL('../../../rules/secrets/twilio-key.json', import.meta.url);

/**
 * Proves the hooks being measured really run: a pre-tool-use call carrying a
 * value taken from a bundled rule's own `examples` must come back with a
 * decision on stdout. A hook that exits at once — a missing body, a broken
 * build — also exits 0 with nothing printed, and would otherwise be measured
 * as a very fast hook. Throws, so the run fails, when it does not.
 */
export function assertHooksRun(scriptsDir: string, env: Record<string, string>): void {
  const rule = JSON.parse(readFileSync(CONTROL_RULE_FILE, 'utf8')) as { examples?: unknown };
  const example = Array.isArray(rule.examples) ? (rule.examples[0] as unknown) : undefined;
  if (typeof example !== 'string') throw new Error('the bench control rule has no example');
  const sample = runHook(
    {
      script: join(scriptsDir, 'pre-tool-use.js'),
      payload: JSON.stringify({
        ...HOOK_PAYLOADS['pre-tool-use (Bash)'].payload,
        session_id: 'bench-control',
        tool_input: { command: `echo ${example}` },
      }),
    },
    env,
  );
  if (sample.status !== 0 || sample.stdout.trim() === '') {
    throw new Error(
      `the bench control found nothing in ${scriptsDir}: pre-tool-use exited ` +
        `${String(sample.status)} with no decision for a bundled rule's own example, so the ` +
        'hooks under measurement are not running',
    );
  }
}

/** The payloads the host sends on the paths every session takes most often. */
export const HOOK_PAYLOADS = {
  'pre-tool-use (Bash)': {
    entry: 'pre-tool-use.js',
    payload: {
      session_id: 'bench-session',
      transcript_path: join(tmpdir(), 'aka-bench-transcript.jsonl'),
      cwd: tmpdir(),
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'git status --short', description: 'Show working tree status' },
    },
  },
  'post-tool-use (Read)': {
    entry: 'post-tool-use.js',
    payload: {
      session_id: 'bench-session',
      transcript_path: join(tmpdir(), 'aka-bench-transcript.jsonl'),
      cwd: tmpdir(),
      hook_event_name: 'PostToolUse',
      tool_name: 'Read',
      tool_input: { file_path: join(tmpdir(), 'example.ts') },
      tool_response: {
        type: 'text',
        file: {
          filePath: join(tmpdir(), 'example.ts'),
          content:
            'export function add(a: number, b: number): number {\n  return a + b;\n}\n'.repeat(40),
          numLines: 120,
          startLine: 1,
          totalLines: 120,
        },
      },
    },
  },
  stop: {
    entry: 'stop.js',
    payload: {
      session_id: 'bench-session',
      transcript_path: join(tmpdir(), 'aka-bench-transcript.jsonl'),
      cwd: tmpdir(),
      hook_event_name: 'Stop',
      stop_hook_active: false,
    },
  },
} as const;

export type HookVariant = keyof typeof HOOK_PAYLOADS;
