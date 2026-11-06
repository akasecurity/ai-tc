// `cli-latest` only moves forward. The npm step skips a version already published, so a
// re-run of an older tag's failed job reaches the move, and a plain force-push there moves
// the alias back to the older commit. `release-binaries-integrity.test.js` holds the same
// rule for `bin-latest`.
//
// Executed rather than read, because the ordering is the part that cannot be read: a `sort`
// without the numeric keys orders 0.9.9 after 0.9.12.

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
import { delimiter, dirname, join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { jobOf, parseWorkflow, scriptOf, stepIndex, stepNamed } from './helpers/workflow-yaml.js';

const WORKFLOW = join(REPO_ROOT, '.github', 'workflows', 'release-cli.yml');
const DECIDE = 'Decide whether cli-latest moves forward';
const MOVE = 'Point cli-latest at this release';
const LEASE = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';

const job = () => jobOf(parseWorkflow(readFileSync(WORKFLOW, 'utf8')), 'release');

const SCRATCH = [];
afterAll(() => {
  for (const dir of SCRATCH) rmSync(dir, { recursive: true, force: true });
});

/** @param {{ skip: (note?: string) => void }} ctx */
function requireBash(ctx) {
  if (process.platform === 'win32' || !existsSync('/bin/bash')) ctx.skip('needs a POSIX shell');
}

/** A directory holding the CLI manifest and a stub `git` that answers for origin. */
function fixture(version) {
  const root = mkdtempSync(join(tmpdir(), 'aka-cli-latest-'));
  SCRATCH.push(root);
  mkdirSync(join(root, 'bin'));
  mkdirSync(join(root, 'cli'));
  writeFileSync(join(root, 'cli', 'package.json'), JSON.stringify({ version }));
  writeFileSync(
    join(root, 'bin', 'git'),
    [
      '#!/bin/sh',
      'echo "git $*" >> "$GIT_LOG"',
      'case "$1" in',
      '  ls-remote)',
      '    case "$GIT_MODE" in',
      `      found) printf '%s\\trefs/tags/cli-latest\\n' ${LEASE} ;;`,
      '      missing) exit 2 ;;',
      "      *) echo 'fatal: unable to access origin' >&2; exit 128 ;;",
      '    esac ;;',
      '  fetch | tag | push) exit 0 ;;',
      '  show) printf \'{"version":"%s"}\\n\' "$GIT_CURRENT" ;;',
      '  *) echo "unexpected git $*" >&2; exit 99 ;;',
      'esac',
      '',
    ].join('\n'),
  );
  chmodSync(join(root, 'bin', 'git'), 0o755);
  writeFileSync(join(root, 'output'), '');
  writeFileSync(join(root, 'git.log'), '');
  return root;
}

/** Run one step's script in a fixture. */
function run(root, step, env) {
  return execFileSync('/bin/bash', ['-c', scriptOf(stepNamed(job(), step))], {
    cwd: root,
    encoding: 'utf8',
    stdio: 'pipe',
    env: {
      PATH: [join(root, 'bin'), dirname(process.execPath), '/usr/bin', '/bin'].join(delimiter),
      GITHUB_OUTPUT: join(root, 'output'),
      GIT_LOG: join(root, 'git.log'),
      ...env,
    },
    timeout: 60_000,
  });
}

/** Run the decision and return what it wrote to `$GITHUB_OUTPUT`. */
function decide({ version = '0.9.12', mode = 'found', current = '' }) {
  const root = fixture(version);
  run(root, DECIDE, { GIT_MODE: mode, GIT_CURRENT: current });
  return Object.fromEntries(
    readFileSync(join(root, 'output'), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => line.split('=')),
  );
}

describe('cli-latest only moves forward', () => {
  it.for([
    ['an older release', '0.9.11', 'yes'],
    ['the same release, re-run', '0.9.12', 'yes'],
    ['a newer release', '0.9.13', 'no'],
    ['0.9.9, which sorts after 0.9.12 as text', '0.9.9', 'yes'],
    ['0.10.0, which sorts before 0.9.12 as text', '0.10.0', 'no'],
  ])('against %s (%s), decides move=%s for 0.9.12', ([, current, expected], ctx) => {
    requireBash(ctx);
    const outputs = decide({ current });
    expect(outputs.move).toBe(expected);
    expect(outputs.lease).toBe(LEASE);
  });

  it('moves a tag that does not exist yet, leased against its absence', (ctx) => {
    requireBash(ctx);
    const outputs = decide({ mode: 'missing' });
    expect(outputs.move).toBe('yes');
    expect(outputs.lease).toBe('');
  });

  it('leaves the tag alone for a pre-release', (ctx) => {
    requireBash(ctx);
    expect(decide({ version: '0.9.13-beta.1', current: '0.9.12' }).move).toBe('no');
  });

  // A failed read is not an absent tag: taken for one, it moves the alias with nothing to
  // compare against, backwards as easily as forwards.
  it('refuses to decide when origin cannot be read', (ctx) => {
    requireBash(ctx);
    expect(() => decide({ mode: 'fault' })).toThrow(/could not read cli-latest/);
  });

  it('refuses to order against a version that is not bare', (ctx) => {
    requireBash(ctx);
    expect(() => decide({ current: '0.10.0-beta.1' })).toThrow(/not a bare X\.Y\.Z/);
  });

  it('moves only when the decision says so, on a tag push', () => {
    const terms = stepNamed(job(), MOVE)
      .if.split('&&')
      .map((term) => term.trim())
      .sort();
    expect(terms).toEqual(["github.event_name == 'push'", "steps.advance.outputs.move == 'yes'"]);
    expect(stepNamed(job(), DECIDE).id).toBe('advance');
  });

  it('pushes against the lease the decision read, never with a plain force', (ctx) => {
    requireBash(ctx);
    const root = fixture('0.9.12');
    run(root, MOVE, { LEASE });
    const pushes = readFileSync(join(root, 'git.log'), 'utf8')
      .split('\n')
      .filter((line) => line.startsWith('git push'));
    expect(pushes).toEqual([
      `git push --force-with-lease=refs/tags/cli-latest:${LEASE} origin refs/tags/cli-latest`,
    ]);
  });

  it('decides after npm, and moves before the Release is published', () => {
    const order = ['Publish to npm', DECIDE, MOVE, 'Publish GitHub Release'].map((name) =>
      stepIndex(job(), name),
    );
    expect(order).toEqual([...order].sort((a, b) => a - b));
  });

  it('takes the lease from the decision', () => {
    expect(stepNamed(job(), MOVE).env.LEASE).toBe('${{ steps.advance.outputs.lease }}');
  });
});
