// Every CI invocation of `turbo run test` must bound its concurrency.
//
// Two layers of parallelism multiply on a CI runner. Turbo runs PACKAGE tasks
// concurrently (its default is 10), and each package's vitest then spawns a
// worker pool sized to the machine. Unbounded, that puts tens of processes on a
// hosted runner with four cores — and they contend for DISK rather than CPU,
// because this repository never mocks node:sqlite or the filesystem, so every
// store test does real fsync-heavy I/O in a real temp dir.
//
// The symptom is not a wrong answer, which is what made it hard to act on: it
// is a rotating cast of unrelated suites reporting `Hook timed out`, on a leg
// that goes green if you press the button again. A timeout under that much
// oversubscription measures queue depth, not the code under test.
//
// So the bound is asserted here rather than left to review. A fifth job, or a
// fifth invocation inside an existing one, is exactly the shape that would
// reintroduce this silently — the workflow still passes, just less often, and
// nothing in a diff says so. `ci.yml` is already in this task's turbo `inputs`
// (alongside the other workflows), so editing it re-runs this check rather than
// replaying a cached pass.
//
// Deliberately NOT a check on the number: what counts as the right cap depends
// on the runner and is settled by measuring the pass rate. What is asserted is
// that a bound EXISTS and parses as a positive integer, since `--concurrency`
// with no value, or with a non-number, is a silent no-op away from the default.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';

const WORKFLOW_REL = '.github/workflows/ci.yml';

/**
 * Every `run:` command in a workflow, with folded/literal blocks joined.
 *
 * A YAML `run: >` or `run: |` scalar continues onto every following line that
 * is indented deeper than the `run:` key itself, which is why this cannot be a
 * line-wise grep: the Windows leg spells its command across a dozen lines, so a
 * per-line scan sees `pnpm turbo run test` and `--concurrency=2` as unrelated
 * strings and can be satisfied — or fooled — by either alone.
 * @param {string} text workflow file contents
 * @returns {string[]} one entry per `run:` key, whitespace-collapsed
 */
export function runCommands(text) {
  const lines = text.split('\n');
  const commands = [];

  for (let i = 0; i < lines.length; i += 1) {
    const start = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(lines[i]);
    if (!start) continue;

    const indent = start[1].length;
    const parts = [start[2].replace(/^[>|][-+]?\s*$/, '')];

    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j];
      // A blank line inside a block scalar is part of it; the block ends at the
      // first non-blank line indented no deeper than the `run:` key.
      if (line.trim() === '') {
        parts.push('');
        continue;
      }
      const lead = /^\s*/.exec(line)[0].length;
      if (lead <= indent) break;
      parts.push(line.trim());
      i = j;
    }

    const joined = parts.join(' ').replace(/\s+/g, ' ').trim();
    if (joined !== '') commands.push(joined);
  }

  return commands;
}

/** True for a command that runs the workspace `test` task through turbo. */
const runsTurboTest = (cmd) => /\bturbo\s+run\s+(?:[\w:@/-]+\s+)*test\b/.test(cmd);

/** The value of `--concurrency`, in either the `=` or space-separated form. */
const concurrencyOf = (cmd) => /--concurrency[=\s]+(\S+)/.exec(cmd)?.[1];

describe('CI bounds the concurrency of every turbo test run', () => {
  const text = readFileSync(join(REPO_ROOT, WORKFLOW_REL), 'utf8');
  const commands = runCommands(text);

  it('reads a workflow it really parsed', () => {
    // Every assertion below is over a filtered list, and an empty list passes
    // all of them. This is what stops the suite going green on a regex that
    // stopped matching, or on a workflow that was renamed out from under it.
    expect(commands.length, `${WORKFLOW_REL} yielded no run: commands`).toBeGreaterThan(5);
    expect(
      commands.some((c) => c.includes('pnpm install --frozen-lockfile')),
      'the parser did not find the install step every job carries',
    ).toBe(true);
  });

  it('finds the test invocations, so the bound below is not guarding an absence', () => {
    // The positive control, and it is a floor rather than an exact count on
    // purpose: adding a leg is normal, and it must fail the bound assertion
    // below rather than this one.
    const testRuns = commands.filter(runsTurboTest);
    expect(
      testRuns.length,
      `no \`turbo run test\` invocation found in ${WORKFLOW_REL}`,
    ).toBeGreaterThanOrEqual(4);
  });

  it('bounds every one of them', () => {
    const unbounded = commands.filter(runsTurboTest).filter((c) => concurrencyOf(c) === undefined);
    expect(
      unbounded,
      'a `turbo run test` invocation with no --concurrency lets turbo fall back to its ' +
        'default (10) package tasks at once, each spawning its own vitest pool:\n  ' +
        unbounded.join('\n  '),
    ).toEqual([]);
  });

  it('gives each a value that is actually a positive integer', () => {
    // `--concurrency` with a missing or non-numeric value is a no-op away from
    // the default, and reads in a diff exactly like a bound.
    const bad = commands
      .filter(runsTurboTest)
      .map((c) => [c, concurrencyOf(c)])
      .filter(([, v]) => v !== undefined && !/^[1-9]\d*$/.test(v));
    expect(
      bad.map(([, v]) => v),
      `--concurrency needs a positive integer`,
    ).toEqual([]);
  });

  it('sends the flag to turbo rather than through a package script', () => {
    // `pnpm test -- --concurrency=2` forwards the flag to each TASK's own
    // command (`vitest run --concurrency=2`), not to turbo — the same trap the
    // no-network job documents for `--force`. Such a line reads as bounded and
    // is not, so the flag must sit on a command that names turbo directly.
    const detached = commands
      .filter((c) => concurrencyOf(c) !== undefined)
      .filter((c) => !runsTurboTest(c));
    expect(
      detached,
      '--concurrency on a command that does not invoke `turbo run test` is forwarded to the ' +
        `task, not to turbo:\n  ${detached.join('\n  ')}`,
    ).toEqual([]);
  });
});

describe('runCommands', () => {
  // The parser decides what every assertion above sees, so its edges are pinned
  // rather than assumed — wrong in the joining direction and a multi-line
  // command is read as several unrelated ones.
  it('joins a folded block into one command', () => {
    const yaml = [
      '      - name: Test',
      '        run: >',
      '          pnpm turbo run test',
      '          --concurrency=2',
      '',
      '      - name: Build',
      '        run: pnpm build',
    ].join('\n');
    expect(runCommands(yaml)).toEqual(['pnpm turbo run test --concurrency=2', 'pnpm build']);
  });

  it('does not merge two sibling run: keys', () => {
    const yaml = ['        run: pnpm lint', '        run: pnpm turbo run test'].join('\n');
    expect(runCommands(yaml)).toEqual(['pnpm lint', 'pnpm turbo run test']);
  });

  it('ends a block at a line indented no deeper than its own run: key', () => {
    const yaml = [
      '        run: |',
      '          pnpm turbo run test',
      '        env:',
      '          FOO: bar',
    ].join('\n');
    expect(runCommands(yaml)).toEqual(['pnpm turbo run test']);
  });
});

describe('runsTurboTest', () => {
  it.each([
    ['pnpm turbo run test --concurrency=2', true],
    ['pnpm turbo run test --continue --concurrency=2', true],
    ['tools/ci/no-network-test.sh pnpm exec turbo run test --force --concurrency=2', true],
    // A task list naming test among others still runs it.
    ['pnpm turbo run build test --concurrency=2', true],
    // Not the test task.
    ['pnpm turbo run typecheck', false],
    ['pnpm turbo run build', false],
    // A package script wrapping it is not a turbo invocation this can bound.
    ['pnpm test', false],
  ])('%s -> %s', (cmd, expected) => {
    expect(runsTurboTest(cmd)).toBe(expected);
  });
});
