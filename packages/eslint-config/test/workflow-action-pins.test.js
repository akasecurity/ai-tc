// Every `uses:` in every workflow is pinned to a full commit SHA with the full
// version in its trailing comment (`uses: owner/action@<40 hex> # v1.2.3`).
//
// release-binaries-integrity.test.js pins five named steps; this walks the whole
// directory so a new `uses: actions/cache@v6` anywhere fails here, and so the
// comment keeps one form (the full version, which also records the patch the pin
// is parked on) for Dependabot to rewrite.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { isMapping, jobsOf, parseWorkflow, usesOf } from './helpers/workflow-yaml.js';

const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');

const PINNED = /^[\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/;

/**
 * Every `uses` in a workflow's text as parsed YAML: each step's and each
 * reusable-workflow job's, however it is spelled (block, flow-style, value on the
 * next line, block scalar). The trailing comment is kept with the value.
 * @param {string} source
 * @returns {string[]}
 */
export function usesIn(source) {
  const workflow = parseWorkflow(source);
  return Object.values(jobsOf(workflow)).flatMap((job) => {
    if (!isMapping(job)) return [];
    const holders = [job, ...(Array.isArray(job.steps) ? job.steps : [])];
    return holders.filter((h) => isMapping(h) && Object.hasOwn(h, 'uses')).map(usesOf);
  });
}

/** A pin is local (`./path`), or an action pinned as PINNED says. */
export const isPinned = (value) => value.startsWith('./') || PINNED.test(value);

describe('the pin check', () => {
  it.each([
    'actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0',
    'actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0',
    './.github/actions/local',
  ])('accepts %s', (value) => {
    expect(isPinned(value)).toBe(true);
  });

  it.each([
    'actions/cache@v6',
    'actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9',
    'actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6',
    'actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a # v6.1.0',
    'actions/cache@main # v6.1.0',
  ])('refuses %s', (value) => {
    expect(isPinned(value)).toBe(false);
  });

  it('reads every spelling of uses, so none escapes the check', () => {
    const wf = (...steps) => ['jobs:', '  j:', '    runs-on: x', '    steps:', ...steps].join('\n');
    const reads = (...steps) => usesIn(wf(...steps)).map(isPinned);
    expect(reads('      - uses: actions/cache@v6')).toEqual([false]);
    expect(reads('      - { uses: actions/checkout@v7 }')).toEqual([false]);
    expect(reads('      - uses:', '          owner/repo@v6')).toEqual([false]);
    expect(reads('      - uses: >', '          owner/repo@v6')).toEqual([false]);
    expect(reads('      - uses: |', '          owner/repo@v6')).toEqual([false]);
    expect(reads("      - run: 'echo uses: x'")).toEqual([]);
    expect(
      reads('      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0'),
    ).toEqual([true]);
    expect(
      usesIn(['jobs:', '  j:', '    uses: o/r/.github/workflows/w.yml@v1'].join('\n')),
    ).toEqual(['o/r/.github/workflows/w.yml@v1']);
  });
});

describe('the workflows', () => {
  const files = readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f));

  it('has workflows to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files)('%s pins every uses: to a SHA with the full version', (file) => {
    const bad = usesIn(readFileSync(join(WORKFLOWS, file), 'utf8')).filter((v) => !isPinned(v));
    expect(bad).toEqual([]);
  });
});
