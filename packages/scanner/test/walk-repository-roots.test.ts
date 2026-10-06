import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { walkSourceFiles, walkTree } from '../src/walk.ts';

// The walker names every directory below its root that it lists and that holds
// a `.git` entry: a nested clone (a directory), or a submodule or linked
// worktree (a file). The scanner reports those repositories beside the Data
// Shares register (./egress.test.ts); this pins the walker's half on its own.
describe('walkTree — repository roots below the walk root', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-walk-roots-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function write(rel: string, content = 'export const x = 1;\n'): void {
    const full = join(tmp, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }

  // A clone's `.git` is a directory; what is in it does not matter to the walk.
  function clone(rel: string): void {
    mkdirSync(join(tmp, rel, '.git'), { recursive: true });
  }

  function rootsFound(excludePatterns?: string[]): string[] {
    const roots: string[] = [];
    Array.from(
      walkTree(tmp, {
        excludePatterns,
        onRepositoryRoot: (dir) => {
          roots.push(dir);
        },
      }),
    );
    return roots.sort();
  }

  it('names a nested clone and a submodule by their posix paths below the root', () => {
    clone('.');
    clone('tools/mine');
    write('lib/.git', 'gitdir: ../.git/modules/lib\n');
    write('src/app.ts');

    expect(rootsFound()).toEqual(['lib', 'tools/mine']);
  });

  it("never names the walk root, whose repository is the walk's own", () => {
    clone('.');
    write('src/app.ts');

    expect(rootsFound()).toEqual([]);
  });

  it('names a repository nested inside a nested one', () => {
    clone('tools/mine');
    clone('tools/mine/deps/inner');

    expect(rootsFound()).toEqual(['tools/mine', 'tools/mine/deps/inner']);
  });

  it('names nothing in a directory the walk does not enter', () => {
    // Inside a skipped directory: SKIP_DIRS, .akaignore, the host's patterns.
    clone('node_modules/dep');
    write('.akaignore', 'private/\nscratch/\n');
    clone('private/notes');
    clone('legacy/old');
    // And repositories that ARE the skipped directory. A root is named off its
    // own listing, so only once the walk is inside it; a walker that looked
    // for `.git` from the parent's side, ahead of its skips, would name these.
    clone('vendor');
    clone('scratch');
    clone('archive');

    expect(rootsFound(['legacy/', 'archive/'])).toEqual([]);
  });

  it('walks the same files whether or not anyone is told about repositories', () => {
    clone('tools/mine');
    write('tools/mine/a.ts');
    write('src/b.ts');
    const paths = (told: boolean): string[] =>
      [...walkTree(tmp, told ? { onRepositoryRoot: () => undefined } : {})]
        .map((file) => file.path)
        .sort();

    expect(paths(true)).toEqual(paths(false));
  });

  it('names the same roots from the source walk, and the files it yields do not change', () => {
    // The source walk takes the host's patterns and the manifest walk does not,
    // so the two can list different directories; the scanner listens to both.
    clone('tools/mine');
    write('tools/mine/a.ts');
    write('src/b.ts');
    const roots: string[] = [];

    const told = [
      ...walkSourceFiles({
        rootDir: tmp,
        onRepositoryRoot: (dir) => {
          roots.push(dir);
        },
      }),
    ].map((file) => file.path);
    const untold = [...walkSourceFiles({ rootDir: tmp })].map((file) => file.path);

    expect(roots).toEqual(['tools/mine']);
    expect(told.sort()).toEqual(untold.sort());
  });
});
