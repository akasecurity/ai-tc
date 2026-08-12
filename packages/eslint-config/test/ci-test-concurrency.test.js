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
// nothing in a diff says so.
//
// The DIRECTORY is read, not one filename. An unbounded run is the same hazard
// in a release workflow as in ci.yml, and four of those gate a publish on tag
// push; reading the directory also means a workflow added tomorrow is covered
// without editing this file. `turbo.json` hashes the same directory with a
// glob, so editing any workflow re-runs this check rather than replaying a
// cached pass — the two are one decision in two files, and a workflow this
// suite reads that turbo does not hash is a guard that never runs on the edit
// it exists to catch.
//
// Two spellings reach the same task, and only one of them contains the word
// `turbo`:
//
//   pnpm turbo run test    — takes --concurrency, which is what bounds it
//   pnpm test              — the root script, which is itself `turbo run test`
//
// The second is rejected outright rather than checked for a flag, because it
// cannot carry one: `pnpm test -- --concurrency=2` forwards the flag to each
// TASK's own command (`vitest run --concurrency=2`), not to turbo. A line like
// that reads in a diff exactly like a bound and is not one.
//
// Deliberately NOT a check on the number: what counts as the right cap depends
// on the runner and is settled by measuring the pass rate. What is asserted is
// that a bound EXISTS and parses as a positive integer, since `--concurrency`
// with no value, or with a non-number, is a silent no-op away from the default.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';

const WORKFLOW_DIR = '.github/workflows';

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

/**
 * Every `run:` command in every workflow, tagged with the file it came from.
 *
 * The directory is listed rather than enumerated, so a workflow added tomorrow
 * is covered without editing this file. Failures carry the filename because a
 * bare command is not actionable once this reads more than one workflow.
 * @returns {{file: string, cmd: string}[]} one entry per `run:` key
 */
function workflowCommands() {
  const dir = join(REPO_ROOT, WORKFLOW_DIR);
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
    .sort();
  return files.flatMap((file) =>
    runCommands(readFileSync(join(dir, file), 'utf8')).map((cmd) => ({ file, cmd })),
  );
}

/** `file: command`, the form every failure below reports. */
const describeHit = ({ file, cmd }) => `${file}: ${cmd}`;

/** True for a command that runs the workspace `test` task through turbo. */
const runsTurboTest = (cmd) => /\bturbo\s+run\s+(?:[\w:@/-]+\s+)*test\b/.test(cmd);

/**
 * True for a command that reaches the `test` task through the package script.
 *
 * `pnpm test` and `pnpm run test` both run the root script, which is
 * `turbo run test` — so this is an unbounded workspace test run that never says
 * the word turbo. The lookahead keeps `pnpm test:e2e` and friends out: those are
 * different scripts, and a colon is not a word character, so `\btest\b` alone
 * matches them.
 */
const runsTestViaPackageScript = (cmd) =>
  /\bpnpm\s+(?:run\s+)?test\b(?!\s*:)/.test(cmd) && !runsTurboTest(cmd);

/** The value of `--concurrency`, in either the `=` or space-separated form. */
const concurrencyOf = (cmd) => /--concurrency[=\s]+(\S+)/.exec(cmd)?.[1];

describe('CI bounds the concurrency of every turbo test run', () => {
  const hits = workflowCommands();

  it('reads workflows it really parsed', () => {
    // Every assertion below is over a filtered list, and an empty list passes
    // all of them. This is what stops the suite going green on a regex that
    // stopped matching, on a directory that moved, or on an extension filter
    // that stopped matching the files in it.
    const files = [...new Set(hits.map((h) => h.file))];
    expect(files.length, `${WORKFLOW_DIR} yielded no parseable workflows`).toBeGreaterThan(5);
    expect(files, `${WORKFLOW_DIR} no longer yields ci.yml`).toContain('ci.yml');
    expect(hits.length, `${WORKFLOW_DIR} yielded no run: commands`).toBeGreaterThan(20);
    expect(
      hits.some((h) => h.cmd.includes('pnpm install --frozen-lockfile')),
      'the parser did not find the install step every job carries',
    ).toBe(true);
  });

  it('finds the test invocations, so the bounds below are not guarding an absence', () => {
    // The positive control, and it is a floor rather than an exact count on
    // purpose: adding a leg is normal, and it must fail a bound assertion below
    // rather than this one. The message names the count it found, because
    // "found none" and "found fewer than expected" send a reader to different
    // places and this fires for both.
    const testRuns = hits.filter((h) => runsTurboTest(h.cmd));
    expect(
      testRuns.length,
      `expected at least 4 \`turbo run test\` invocations across ${WORKFLOW_DIR}, found ` +
        `${testRuns.length}:\n  ${testRuns.map(describeHit).join('\n  ') || '(none)'}`,
    ).toBeGreaterThanOrEqual(4);
  });

  it('bounds every one of them', () => {
    const unbounded = hits.filter(
      (h) => runsTurboTest(h.cmd) && concurrencyOf(h.cmd) === undefined,
    );
    expect(
      unbounded.map(describeHit),
      'a `turbo run test` invocation with no --concurrency lets turbo fall back to its ' +
        'default (10) package tasks at once, each spawning its own vitest pool',
    ).toEqual([]);
  });

  it('gives each a value that is actually a positive integer', () => {
    // `--concurrency` with a missing or non-numeric value is a no-op away from
    // the default, and reads in a diff exactly like a bound.
    const bad = hits
      .filter((h) => runsTurboTest(h.cmd))
      .filter((h) => {
        const v = concurrencyOf(h.cmd);
        return v !== undefined && !/^[1-9]\d*$/.test(v);
      });
    expect(bad.map(describeHit), `--concurrency needs a positive integer`).toEqual([]);
  });

  it('sends the flag to turbo rather than through a package script', () => {
    // `pnpm test -- --concurrency=2` forwards the flag to each TASK's own
    // command (`vitest run --concurrency=2`), not to turbo — the same trap the
    // no-network job documents for `--force`. Such a line reads as bounded and
    // is not, so the flag must sit on a command that names turbo directly.
    const detached = hits.filter(
      (h) => concurrencyOf(h.cmd) !== undefined && !runsTurboTest(h.cmd),
    );
    expect(
      detached.map(describeHit),
      '--concurrency on a command that does not invoke `turbo run test` is forwarded to the ' +
        'task, not to turbo',
    ).toEqual([]);
  });

  it('never reaches the test task through a package script', () => {
    // The hole the assertions above cannot see. `pnpm test` runs the root
    // script, which is `turbo run test` over all 20 packages — an unbounded
    // workspace test run that matches no `turbo` predicate, so every filter
    // above skips it and the suite goes green. It is also the spelling this
    // repo used until these bounds landed, which makes it the most likely way
    // back in. There is no bounded form of it: the flag would reach the task
    // rather than turbo, so the fix is always to spell the turbo call.
    const viaScript = hits.filter((h) => runsTestViaPackageScript(h.cmd));
    expect(
      viaScript.map(describeHit),
      '`pnpm test` runs the root script (`turbo run test`) with no bound, and cannot take ' +
        'one — write `pnpm turbo run test --concurrency=N` instead',
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

describe('runsTestViaPackageScript', () => {
  it.each([
    // The root script, in both spellings pnpm accepts.
    ['pnpm test', true],
    ['pnpm run test', true],
    // Already the trap the flag assertion catches; it is still a script run.
    ['pnpm test -- --concurrency=2', true],
    // A turbo call is bounded by the assertions above, not by this one — and
    // both spellings contain the word `test`, so without the turbo exclusion
    // every bounded invocation in the tree would report here.
    ['pnpm turbo run test --concurrency=2', false],
    ['pnpm exec turbo run test --force --concurrency=2', false],
    // A DIFFERENT script that merely starts with the same four letters. A colon
    // is not a word character, so `\btest\b` matches these on its own.
    ['pnpm test:e2e', false],
    ['pnpm run test:unit', false],
    // Not the test task at all.
    ['pnpm lint', false],
    ['pnpm build', false],
  ])('%s -> %s', (cmd, expected) => {
    expect(runsTestViaPackageScript(cmd)).toBe(expected);
  });
});
