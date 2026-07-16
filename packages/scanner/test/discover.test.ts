import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { discoverGitRepos } from '../src/discover.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-discover-test-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function repo(rel: string): void {
  mkdirSync(join(tmp, rel, '.git'), { recursive: true });
}

describe('discoverGitRepos', () => {
  it('finds repos only under the explicit search roots', () => {
    repo('inside/project-a');
    repo('outside/project-b');

    const found = discoverGitRepos({ searchRoots: [join(tmp, 'inside')] });
    expect(found).toEqual([join(tmp, 'inside/project-a')]);
  });

  it('respects maxDepth', () => {
    repo('a/b/c/d/e/deep-repo'); // depth 6 from tmp
    repo('shallow-repo'); // depth 1

    const found = discoverGitRepos({ searchRoots: [tmp], maxDepth: 2 });
    expect(found).toEqual([join(tmp, 'shallow-repo')]);
  });

  it('stops recursing at a repo root (nested repos not separately enumerated)', () => {
    repo('outer');
    repo('outer/nested');

    const found = discoverGitRepos({ searchRoots: [tmp] });
    expect(found).toEqual([join(tmp, 'outer')]);
  });
});
