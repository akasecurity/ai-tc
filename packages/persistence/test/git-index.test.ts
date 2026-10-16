import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { encodeIndex } from '../../../test/helpers/git-index.ts';
import { createTrackedFileLookup, parseGitIndex } from '../src/git-index.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-git-index-');

function repo(name: string, tracked: string[], version: 2 | 3 | 4 = 2): string {
  const root = join(store.home, name);
  mkdirSync(join(root, '.git'), { recursive: true });
  writeFileSync(join(root, '.git', 'index'), encodeIndex(tracked, version));
  return root;
}

describe('parseGitIndex', () => {
  it.each([2, 3, 4] as const)('reads every path of a version %i index', (version) => {
    const paths = ['src/a.ts', 'src/ab.ts', 'README.md', 'deep/er/file.env'];
    expect(parseGitIndex(encodeIndex(paths, version))).toEqual(new Set(paths));
  });

  it('reads a version 4 index whose shared prefixes cut through non-ASCII paths', () => {
    const paths = ['café/menu.ts', 'café/zz.ts', 'x.ts', 'xé.ts', 'y.ts'];
    expect(parseGitIndex(encodeIndex(paths, 4))).toEqual(new Set(paths));
  });

  it('reads a version 4 entry whose strip count spans more than one varint byte', () => {
    const paths = [`${'a'.repeat(200)}.ts`, 'b.ts'];
    expect(parseGitIndex(encodeIndex(paths, 4))).toEqual(new Set(paths));
  });

  it('reads an entry carrying extended flags', () => {
    expect(parseGitIndex(encodeIndex(['a.ts', 'b.ts'], 3, true))).toEqual(
      new Set(['a.ts', 'b.ts']),
    );
  });

  it('refuses anything that is not an index it can read in full', () => {
    expect(parseGitIndex(Buffer.from('not an index'))).toBeUndefined();
    const truncated = encodeIndex(['src/a.ts', 'src/b.ts']).subarray(0, 40);
    expect(parseGitIndex(truncated)).toBeUndefined();
    const future = encodeIndex(['a.ts']);
    future.writeUInt32BE(5, 4);
    expect(parseGitIndex(future)).toBeUndefined();
  });
});

describe('createTrackedFileLookup', () => {
  it('answers tracked only for a path in the index of the repository holding it', () => {
    const root = repo('widgets', ['src/config.ts', 'deploy/.secrets/key']);
    writeFileSync(join(root, '.gitignore'), '.env\n');
    const tracked = createTrackedFileLookup();

    expect(tracked(join(root, 'src', 'config.ts'))).toBe(true);
    expect(tracked(join(root, 'deploy', '.secrets', 'key'))).toBe(true);
    // Never added, and ignored: neither is in the index.
    expect(tracked(join(root, 'src', 'new.ts'))).toBe(false);
    expect(tracked(join(root, '.env'))).toBe(false);
  });

  it('answers false outside any repository', () => {
    const plain = join(store.home, 'plain');
    mkdirSync(plain);
    expect(createTrackedFileLookup()(join(plain, 'a.ts'))).toBe(false);
    repo('widgets', ['a.ts']);
    expect(createTrackedFileLookup()(join(store.home, 'elsewhere', 'a.ts'))).toBe(false);
  });

  it('reads a nested repository by its own index', () => {
    const root = repo('outer', ['top.ts']);
    const nested = join(root, 'tools', 'inner');
    mkdirSync(join(nested, '.git'), { recursive: true });
    writeFileSync(join(nested, '.git', 'index'), encodeIndex(['lib.ts']));
    const tracked = createTrackedFileLookup();

    expect(tracked(join(nested, 'lib.ts'))).toBe(true);
    expect(tracked(join(root, 'tools', 'inner', 'top.ts'))).toBe(false);
    expect(tracked(join(root, 'top.ts'))).toBe(true);
  });

  it('follows a .git file to the index of a linked worktree', () => {
    const gitdir = join(store.home, 'main', '.git', 'worktrees', 'feature');
    mkdirSync(gitdir, { recursive: true });
    writeFileSync(join(gitdir, 'index'), encodeIndex(['a.ts']));
    const worktree = join(store.home, 'feature');
    mkdirSync(worktree);
    writeFileSync(join(worktree, '.git'), `gitdir: ${gitdir}\n`);

    expect(createTrackedFileLookup()(join(worktree, 'a.ts'))).toBe(true);
  });

  it('claims nothing tracked when the index cannot be read', () => {
    const root = join(store.home, 'broken');
    mkdirSync(join(root, '.git'), { recursive: true });
    writeFileSync(join(root, '.git', 'index'), 'garbage');
    expect(createTrackedFileLookup()(join(root, 'a.ts'))).toBe(false);
    const missing = join(store.home, 'fresh');
    mkdirSync(join(missing, '.git'), { recursive: true });
    expect(createTrackedFileLookup()(join(missing, 'a.ts'))).toBe(false);
  });

  it('reads a repository above the scanned directory, such as a home kept in git', () => {
    const home = repo('dotfiles', ['.aws/credentials']);
    mkdirSync(join(home, '.aws'));
    expect(createTrackedFileLookup()(join(home, '.aws', 'credentials'))).toBe(true);
  });

  it('reads each repository index once', () => {
    const root = repo('once', ['a.ts', 'b.ts']);
    const tracked = createTrackedFileLookup();
    expect(tracked(join(root, 'a.ts'))).toBe(true);
    writeFileSync(join(root, '.git', 'index'), encodeIndex([]));
    expect(tracked(join(root, 'b.ts'))).toBe(true);
  });
});
