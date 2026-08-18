import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { applyPluginUpdate, installAgentPlugin } from '../src/apply.ts';
import { createCliPluginManager } from '../src/cli-plugin-manager.ts';
import {
  assertShimResolves,
  SHIM_NEEDS_SHELL,
  WINDOWS_SYSTEM_DIRS,
  WINDOWS_SYSTEM_ENV,
  writeCommandShim,
} from './helpers/path-shim.ts';

/**
 * What actually reaches a child process.
 *
 * Everything else about the verb table is asserted as STRINGS — the recipes,
 * the spawn plans, the hint copy. That is one derivation short of the claim
 * this package makes: the Updates page shows `installSpawnPlan` under "this
 * runs the following on your machine", and nothing there proves `apply.ts`
 * spawns that. It is also where the defect this table replaced actually bit,
 * one layer down: `codex plugin install` rendered fine and was rejected by the
 * host.
 *
 * So these cases read the argv off the far side of the process boundary.
 *
 * ## Why PATH, and why a CLOSED one
 *
 * `src/exec.ts` takes no injectable runner — `binExists`, `runCapture` and
 * `runInherit` reach `node:child_process` directly and let the child INHERIT
 * this process's env, so there is nowhere to pass a fake to and PATH is the
 * only seam. `vi.stubEnv` is how it is written rather than a `process.env`
 * assignment, which `n/no-process-env` bans workspace-wide.
 *
 * The stubbed PATH carries the shim dir, this process's own node (the shim is
 * a `#!/usr/bin/env node` script) and, on Windows, System32 — and nothing
 * else. That closed set is the point: a shim that fails to land does NOT fail
 * closed on an inherited PATH (see path-shim.ts), it resolves the REAL
 * installed `claude` and the suite spawns a live plugin install against the
 * developer's own machine. With the host PATH left out there is nothing for a
 * miss to fall through to, and `assertShimResolves` names the miss besides.
 */

// The host's own PATH is deliberately absent. `dirname(process.execPath)` is
// read off the running interpreter rather than the environment, so this needs
// no `n/no-process-env` opt-out of its own.
const NODE_DIR = dirname(process.execPath);

// Every spawn in exec.ts is anchored at the user's home on Windows and at this
// process's cwd elsewhere; the probe has to mirror it, because Windows searches
// the working directory BEFORE walking PATH.
const SPAWN_CWD = process.platform === 'win32' ? homedir() : process.cwd();

interface Recorded {
  readonly bin: string;
  readonly args: readonly string[];
}

let dir: string;
let binDir: string;
let failDir: string;
let emptyDir: string;
let callsPath: string;

/**
 * A shim that records its own argv, prints a line, and fails on demand.
 *
 * The fail marker is keyed on argv[1] — `marketplace` for the prep steps,
 * `install`/`update`/`add` for the plugin op — because that is the split
 * `apply.ts` treats differently: prep is best-effort, the op is fatal.
 */
function shimBody(command: string): string {
  return `const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
fs.appendFileSync(
  ${JSON.stringify('__CALLS__')},
  JSON.stringify({ bin: ${JSON.stringify(command)}, args }) + '\\n',
);
process.stdout.write(${JSON.stringify(command)} + ' ' + args.join(' ') + ' ran\\n');
if (fs.existsSync(path.join(${JSON.stringify('__FAILDIR__')}, args[1] || '_'))) {
  process.stderr.write('step refused\\n');
  process.exit(3);
}
`;
}

function calls(): Recorded[] {
  let raw: string;
  try {
    raw = readFileSync(callsPath, 'utf8');
  } catch (err) {
    // Nothing spawned is a legitimate outcome (the not-on-PATH cases below turn
    // on it), so an absent file reads as "no calls" — but only that one code.
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  return raw
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Recorded);
}

/** The recorded calls as the command lines a spawn plan renders. */
function commandLines(): string[] {
  return calls().map((c) => `${c.bin} ${c.args.join(' ')}`);
}

function failStep(token: string): void {
  writeFileSync(join(failDir, token), '');
}

/** Stub PATH with the closed set, and prove each host binary resolves to a shim. */
function armShims(commands: readonly string[]): void {
  const path = [binDir, NODE_DIR, ...WINDOWS_SYSTEM_DIRS].join(delimiter);
  vi.stubEnv('PATH', path);
  const probeEnv: NodeJS.ProcessEnv = { PATH: path, ...WINDOWS_SYSTEM_ENV };
  for (const command of commands) {
    assertShimResolves(command, probeEnv, { shell: SHIM_NEEDS_SHELL, cwd: SPAWN_CWD });
  }
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-local-ops-spawn-'));
  binDir = join(dir, 'bin');
  failDir = join(dir, 'fail');
  emptyDir = join(dir, 'empty');
  callsPath = join(dir, 'calls.jsonl');
  for (const sub of [binDir, failDir, emptyDir]) mkdirSync(sub);
  for (const command of ['claude', 'codex']) {
    writeCommandShim(
      binDir,
      command,
      shimBody(command).replace('__CALLS__', callsPath).replace('__FAILDIR__', failDir),
    );
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
  rmSync(dir, { recursive: true, force: true });
});

describe('what an install/update really spawns', () => {
  it('runs Claude Code’s own verbs, in the order the Updates dialog promises', () => {
    armShims(['claude']);

    const res = installAgentPlugin('claude-code', 'capture');

    expect(res.ok).toBe(true);
    // Spelled out rather than derived, so this pins the verbs themselves: a
    // table edit that renamed `marketplace update` would keep a derived
    // assertion green while changing what runs.
    expect(commandLines()).toEqual([
      'claude plugin marketplace add akasecurity/marketplace',
      'claude plugin marketplace update akasecurity',
      'claude plugin install ai-tc@akasecurity',
    ]);
    // …and the same list is what the confirm dialog renders. This is the join
    // the string-level suites cannot make.
    expect(commandLines()).toEqual(
      createCliPluginManager('claude').installSpawnPlan(
        'ai-tc@akasecurity',
        'akasecurity/marketplace',
        'akasecurity',
      ),
    );
    // Capture mode returns the child's output rather than swallowing it.
    expect(res.output).toContain('claude plugin install ai-tc@akasecurity ran');
  });

  it('updates Claude Code through `plugin update`, refreshing the snapshot first', () => {
    armShims(['claude']);

    const res = applyPluginUpdate('claude-code', 'capture');

    expect(res.ok).toBe(true);
    expect(commandLines()).toEqual([
      'claude plugin marketplace add akasecurity/marketplace',
      'claude plugin marketplace update akasecurity',
      'claude plugin update ai-tc@akasecurity',
    ]);
    expect(commandLines()).toEqual(
      createCliPluginManager('claude').updateSpawnPlan(
        'ai-tc@akasecurity',
        'akasecurity/marketplace',
        'akasecurity',
      ),
    );
  });

  it('runs Codex’s verbs, which are its own — never Claude Code’s', () => {
    armShims(['codex']);

    const res = applyPluginUpdate('codex', 'capture');

    expect(res.ok).toBe(true);
    // `upgrade`, not `update`; `add`, not `update`. Both differ from the Claude
    // Code case above, which is the whole reason the table is per host.
    expect(commandLines()).toEqual([
      'codex plugin marketplace add akasecurity/ai-tc',
      'codex plugin marketplace upgrade ai-tc',
      'codex plugin add aka-codex@ai-tc',
    ]);
    const lines = commandLines();
    expect(lines.some((l) => l.startsWith('claude '))).toBe(false);
    expect(lines).not.toContain('codex plugin update aka-codex@ai-tc');
  });

  it('installs Codex with the same `add` it updates with, and spawns nothing else', () => {
    armShims(['codex']);

    expect(installAgentPlugin('codex', 'capture').ok).toBe(true);

    expect(commandLines()).toEqual([
      'codex plugin marketplace add akasecurity/ai-tc',
      'codex plugin marketplace upgrade ai-tc',
      'codex plugin add aka-codex@ai-tc',
    ]);
  });

  it('streams instead of capturing in inherit mode, and still spawns the same plan', () => {
    armShims(['claude']);

    const res = installAgentPlugin('claude-code', 'inherit');

    expect(res.ok).toBe(true);
    // The output already went to the caller's terminal; returning a copy here
    // would be the CLI printing everything twice.
    expect(res.output).toBe('');
    expect(commandLines()).toEqual([
      'claude plugin marketplace add akasecurity/marketplace',
      'claude plugin marketplace update akasecurity',
      'claude plugin install ai-tc@akasecurity',
    ]);
  });
});

describe('which failures are fatal', () => {
  it('carries on when marketplace prep fails — the op still runs, and succeeds', () => {
    armShims(['claude']);
    failStep('marketplace');

    const res = installAgentPlugin('claude-code', 'capture');

    // Both prep steps refused; the op ran anyway and decided the result. This
    // is the whole reason prep is not in the `&&` recipe: a git-fetch error on
    // the refresh must not abort an install that was going to work.
    expect(res.ok).toBe(true);
    expect(commandLines()).toEqual([
      'claude plugin marketplace add akasecurity/marketplace',
      'claude plugin marketplace update akasecurity',
      'claude plugin install ai-tc@akasecurity',
    ]);
    // A refused prep step leaves no trace in the result either — its output is
    // captured and discarded by ensureMarketplace.
    expect(res.output).not.toContain('step refused');
  });

  it('fails the operation when the plugin op itself fails, and says what ran', () => {
    armShims(['claude']);
    failStep('install');

    const res = installAgentPlugin('claude-code', 'capture');

    expect(res.ok).toBe(false);
    expect(res.output).toContain('step refused');
    expect(commandLines()).toContain('claude plugin install ai-tc@akasecurity');
  });

  it('reports the failure in inherit mode too, where there is no output to read', () => {
    armShims(['codex']);
    failStep('add');

    const res = applyPluginUpdate('codex', 'inherit');

    expect(res.ok).toBe(false);
    expect(res.output).toBe('');
  });
});

describe('when the host CLI is not on PATH at all', () => {
  // A PATH of one empty dir: the binaries are unreachable, `binExists` says so,
  // and the question is what happens instead of a spawn.
  function armEmptyPath(): void {
    vi.stubEnv('PATH', emptyDir);
  }

  it('spawns nothing and hands back both recipes, in that host’s verbs', () => {
    armEmptyPath();

    const res = installAgentPlugin('claude-code', 'capture');

    expect(res.ok).toBe(false);
    expect(calls()).toEqual([]);
    expect(res.output).toContain("the `claude` CLI isn't on your PATH");
    expect(res.output).toContain(
      'claude plugin marketplace add akasecurity/marketplace && claude plugin install ai-tc@akasecurity',
    );
    expect(res.output).toContain('or update with');
    expect(res.output).toContain('claude plugin update ai-tc@akasecurity');
  });

  it('says it once for a host whose install and update are the same command', () => {
    armEmptyPath();

    const res = applyPluginUpdate('codex', 'capture');

    expect(res.ok).toBe(false);
    expect(calls()).toEqual([]);
    expect(res.output).toContain(
      'codex plugin marketplace add akasecurity/ai-tc && codex plugin add aka-codex@ai-tc',
    );
    expect(res.output).toContain('that installs or updates');
    // The two-recipe rendering would print the same ~120 characters twice.
    expect(res.output).not.toContain('or update with');
  });
});

describe('the manager’s own spawning verbs', () => {
  it('install/update shell out to the host, one command each', () => {
    armShims(['claude', 'codex']);

    expect(createCliPluginManager('claude').install('ai-tc@akasecurity')).toBe(true);
    expect(createCliPluginManager('codex').update('aka-codex@ai-tc')).toBe(true);

    // No marketplace prep: these are the bare ops, which is what makes them
    // wrong to call on their own from apply.ts.
    expect(commandLines()).toEqual([
      'claude plugin install ai-tc@akasecurity',
      'codex plugin add aka-codex@ai-tc',
    ]);
  });

  it('reports a failing op as false', () => {
    armShims(['claude']);
    failStep('update');

    expect(createCliPluginManager('claude').update('ai-tc@akasecurity')).toBe(false);
  });

  it('ensureMarketplace runs register then refresh, and swallows both results', () => {
    armShims(['codex']);
    failStep('marketplace');

    expect(() => {
      createCliPluginManager('codex').ensureMarketplace('akasecurity/ai-tc', 'ai-tc');
    }).not.toThrow();

    expect(commandLines()).toEqual([
      'codex plugin marketplace add akasecurity/ai-tc',
      'codex plugin marketplace upgrade ai-tc',
    ]);
  });

  it('skips the refresh when there is no marketplace to refresh', () => {
    armShims(['claude']);

    createCliPluginManager('claude').ensureMarketplace('akasecurity/marketplace');

    expect(commandLines()).toEqual(['claude plugin marketplace add akasecurity/marketplace']);
  });
});
