import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { collectFiles, scanPathIntoStore } from '../src/fs-scan.ts';
import { migratedStore } from './helpers/store-templates.ts';

// The walk `aka scan` and the Scan page share reports every repository nested
// below its target: a directory it lists that holds a `.git` entry. The Data
// Shares forward is handed that list (./shares-forward-nested.test.ts),
// because the walk folds those repositories' files into the target's register.

let root: string;
let store: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-fs-nested-'));
  store = mkdtempSync(join(tmpdir(), 'aka-fs-nested-db-'));
  migratedStore.seed(store);
});

afterEach(() => {
  removeTrees([root, store]);
});

function write(rel: string, content = 'export const x = 1;\n'): void {
  const full = join(root, rel);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

// A clone's `.git` is a directory; what is in it does not matter to the walk.
function clone(rel: string): void {
  mkdirSync(join(root, rel, '.git'), { recursive: true });
}

function nestedUnder(target: string): string[] {
  const found: string[] = [];
  Array.from(
    collectFiles(target, {
      onNestedRepository: (dir) => {
        found.push(dir);
      },
    }),
  );
  return found.sort();
}

describe('collectFiles — repositories nested below the target', () => {
  it('reports a nested clone and a submodule, and never the target itself', () => {
    clone('.');
    clone('tools/mine');
    write('lib/.git', 'gitdir: ../.git/modules/lib\n');
    write('src/app.ts');

    expect(nestedUnder(root)).toEqual([join(root, 'lib'), join(root, 'tools', 'mine')]);
  });

  it('reports a repository nested inside a nested one', () => {
    clone('tools/mine');
    clone('tools/mine/deps/inner');

    expect(nestedUnder(root)).toEqual([
      join(root, 'tools', 'mine'),
      join(root, 'tools', 'mine', 'deps', 'inner'),
    ]);
  });

  it('reports nothing in a directory the walk does not enter', () => {
    // Inside a skipped directory: SKIP_DIRS, a dot-directory, .akaignore.
    clone('node_modules/dep');
    clone('.cache/tool');
    write('.akaignore', 'private/\nscratch/\n');
    clone('private/notes');
    // And repositories that ARE the skipped directory. A repository is told
    // off its own listing, so only once the walk is inside it; a walk that
    // looked for `.git` from the parent's side, ahead of its skips, would
    // report these.
    clone('.dotfiles');
    clone('scratch');
    write('src/app.ts');

    expect(nestedUnder(root)).toEqual([]);
  });

  it('reports nothing for a directly named file', () => {
    clone('tools/mine');
    write('tools/mine/a.ts');

    expect(nestedUnder(join(root, 'tools', 'mine', 'a.ts'))).toEqual([]);
  });
});

describe('scanPathIntoStore — nestedRepositories', () => {
  it('returns every repository its walk found nested below the target', async () => {
    clone('.');
    clone('tools/mine');
    write('tools/mine/notify.ts', "export const HOOK = 'https://api.github.com/repos';\n");
    write('src/app.ts');
    const db = openLocalDatabase(store);
    try {
      const result = await scanPathIntoStore(db, root, { rules: [] });
      expect(result.nestedRepositories).toEqual([join(root, 'tools', 'mine')]);
    } finally {
      db.close();
    }
  });

  it('returns an empty list when nothing is nested', async () => {
    write('src/app.ts');
    const db = openLocalDatabase(store);
    try {
      const result = await scanPathIntoStore(db, root, { rules: [] });
      expect(result.nestedRepositories).toEqual([]);
    } finally {
      db.close();
    }
  });
});
