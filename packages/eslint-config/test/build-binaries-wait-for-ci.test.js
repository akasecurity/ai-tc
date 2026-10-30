// build-binaries.yml builds only on a pull request head whose ci.yml run
// succeeded. The gate is a shell step with a `--jq` row protocol and a
// `$GITHUB_OUTPUT` key, and a change to what `gh` prints would leave it
// answering "build" on a red commit without any other check noticing. These
// cases RUN the step, with `gh`, `sleep` and `date` stubbed, rather than read it.

import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { RETIRED_RUNNER_IMAGES, runnerImageForTarget } from './helpers/runner-images.js';
import {
  envOf,
  ifOf,
  jobOf,
  needsOf,
  parseWorkflow,
  scriptOf,
  stepsOf,
} from './helpers/workflow-yaml.js';

const BASH = '/bin/bash';
/**
 * Skip on a host that cannot run the extracted shell (Windows runs this package
 * too). A skip rather than a bare return: a returning body is a PASSING body, so
 * every executing case would report as covered while asserting nothing.
 * @param {{ skip: (note?: string) => void }} ctx
 */
function requirePosixShell(ctx) {
  if (process.platform === 'win32' || !existsSync(BASH)) {
    ctx.skip(`needs ${BASH}; the gate step is POSIX shell, as GitHub runs it`);
  }
}

const HEAD_SHA = '0123456789abcdef0123456789abcdef01234567';

const workflow = () =>
  parseWorkflow(
    readFileSync(join(REPO_ROOT, '.github', 'workflows', 'build-binaries.yml'), 'utf8'),
  );

const gateScript = () => {
  const step = stepsOf(jobOf(workflow(), 'wait-for-ci')).find((s) => s.id === 'wait');
  expect(step, 'wait-for-ci has no step with id `wait`').toBeDefined();
  return scriptOf(step);
};

const SCRATCH_DIRS = [];
afterAll(() => {
  for (const dir of SCRATCH_DIRS) rmSync(dir, { recursive: true, force: true });
});

/**
 * Run the gate step once. `row` is what the stubbed `gh` prints for the run
 * list (empty for "no run yet"); the stubbed clock jumps 200 s per reading, so
 * an empty row crosses the 300 s window on the second pass.
 * @param {string} row
 */
function runGate(row) {
  const dir = mkdtempSync(join(tmpdir(), 'wait-for-ci-'));
  SCRATCH_DIRS.push(dir);
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  const stub = (name, body) => {
    const file = join(bin, name);
    writeFileSync(file, `#!/bin/bash\n${body}\n`);
    chmodSync(file, 0o755);
  };
  const argsLog = join(dir, 'gh-args');
  const clock = join(dir, 'clock');
  writeFileSync(clock, '0');
  stub('gh', `echo "$*" >> "${argsLog}"\nprintf '%s' "$GATE_ROW"`);
  stub('sleep', 'exit 0');
  stub('date', `n=$(cat "${clock}"); echo $((n + 200)) > "${clock}"; echo "$n"`);
  const output = join(dir, 'github-output');
  writeFileSync(output, '');
  const stdout = execFileSync(BASH, ['-c', gateScript()], {
    encoding: 'utf8',
    env: {
      PATH: `${bin}:/usr/bin:/bin`,
      GATE_ROW: row,
      GITHUB_OUTPUT: output,
      GH_TOKEN: 'x',
      GH_REPO: 'o/r',
      HEAD_SHA,
    },
    timeout: 30_000,
  });
  return {
    stdout,
    outputs: readFileSync(output, 'utf8').trim(),
    args: readFileSync(argsLog, 'utf8'),
  };
}

describe('build-binaries wait-for-ci gate', () => {
  it('asks for the pull_request ci.yml run of the head sha', (ctx) => {
    requirePosixShell(ctx);
    const { args } = runGate('completed success');
    expect(args).toContain('--workflow ci.yml');
    expect(args).toContain(`--commit ${HEAD_SHA}`);
    expect(args).toContain('--event pull_request');
  });

  it('builds when ci.yml completed successfully', (ctx) => {
    requirePosixShell(ctx);
    expect(runGate('completed success').outputs).toBe('ci_ok=true');
  });

  // `it.each` hands its body no TestContext, so a per-case skip needs a plain
  // `it` per row.
  for (const row of [
    'completed failure',
    'completed cancelled',
    'completed skipped',
    'completed timed_out',
  ]) {
    it(`stands down on \`${row}\`, saying why`, (ctx) => {
      requirePosixShell(ctx);
      const { outputs, stdout } = runGate(row);
      expect(outputs).toBe('ci_ok=false');
      expect(stdout).toContain('::notice::');
    });
  }

  it('builds anyway when no ci.yml run appears inside the window', (ctx) => {
    requirePosixShell(ctx);
    const { outputs, stdout } = runGate('');
    expect(outputs).toBe('ci_ok=true');
    expect(stdout).toContain('building without waiting');
  });

  it('gates the matrix on the wait, and runs it where the wait is skipped', () => {
    const wf = workflow();
    const build = jobOf(wf, 'build');
    expect(needsOf(build)).toEqual(['wait-for-ci']);
    // The whole condition, not fragments of it: dropping `always()` keeps both
    // fragments in the text while a skipped need starts skipping the build.
    expect(ifOf(build, 'the build job')).toBe(
      "${{ always() && (needs.wait-for-ci.result == 'skipped' || needs.wait-for-ci.outputs.ci_ok == 'true') }}",
    );
  });

  it('runs the wait on pull requests only, against the PR head sha', () => {
    const wait = jobOf(workflow(), 'wait-for-ci');
    expect(ifOf(wait, 'wait-for-ci')).toBe("github.event_name == 'pull_request'");
    const step = stepsOf(wait).find((s) => s.id === 'wait');
    expect(envOf(step).HEAD_SHA).toBe('${{ github.event.pull_request.head.sha }}');
  });

  // Resolved inside the `it`: the readers assert, and an assertion raised from a
  // `describe` body is a collection error that reports the file as `(0 test)` and
  // takes every other case in it with it.
  it('builds darwin-arm64 on a macOS image GitHub has not retired', () => {
    const os = runnerImageForTarget(workflow(), 'build', 'darwin-arm64');
    expect(
      RETIRED_RUNNER_IMAGES.includes(os),
      `the darwin-arm64 leg pins \`${os}\`, a retired macOS image: GitHub terminates a job queued on one rather than giving it a runner`,
    ).toBe(false);
  });

  it('has no push trigger, so there is no ungated push path', () => {
    const on = workflow().on;
    expect(Object.keys(on).sort()).toEqual(['pull_request', 'workflow_dispatch']);
  });
});
