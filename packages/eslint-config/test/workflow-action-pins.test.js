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

const WORKFLOWS = join(REPO_ROOT, '.github', 'workflows');

const PINNED = /^[\w.-]+\/[\w./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/;

/** The `uses:` value (comment included) of a line, or undefined when it has none. */
export const usesValue = (line) => /^\s*(?:-\s+)?uses:\s*(\S.*?)\s*$/.exec(line)?.[1];

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

  it('reads the value of a step line, with or without the list dash', () => {
    expect(usesValue('      - uses: actions/cache@v6')).toBe('actions/cache@v6');
    expect(usesValue('        uses: actions/cache@v6 # v6.1.0')).toBe('actions/cache@v6 # v6.1.0');
    expect(usesValue('      - run: echo uses: x')).toBeUndefined();
  });
});

describe('the workflows', () => {
  const files = readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f));

  it('has workflows to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files)('%s pins every uses: to a SHA with the full version', (file) => {
    const bad = readFileSync(join(WORKFLOWS, file), 'utf8')
      .split('\n')
      .map((line, i) => ({ n: i + 1, value: usesValue(line) }))
      .filter((u) => u.value !== undefined && !isPinned(u.value))
      .map((u) => `${file}:${u.n} ${u.value}`);
    expect(bad).toEqual([]);
  });
});
