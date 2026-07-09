import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveProjectFiles } from './project-files.ts';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-projfiles-'));
  mkdirSync(join(root, '.git'), { recursive: true });
  writeFileSync(join(root, '.git', 'config'), '[core]\n\tbare = false\n');
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function write(rel: string, content = ''): void {
  const full = join(root, rel);
  mkdirSync(join(full, '..'), { recursive: true });
  writeFileSync(full, content);
}

describe('resolveProjectFiles', () => {
  it('returns undefined outside a git repo', () => {
    const bare = mkdtempSync(join(tmpdir(), 'aka-nogit-'));
    try {
      expect(resolveProjectFiles(bare)).toBeUndefined();
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });

  it('returns undefined for an empty worktree (never wipes a stored tree)', () => {
    expect(resolveProjectFiles(root)).toBeUndefined();
  });

  it('walks files with repo-relative posix paths, sorted', () => {
    write('src/app.ts');
    write('README.md');
    const scan = resolveProjectFiles(join(root, 'src'));
    expect(scan?.truncated).toBe(false);
    expect(scan?.files.map((f) => f.path)).toEqual(['README.md', 'src/app.ts']);
    expect(scan?.files.every((f) => f.defaultAccess === 'approved')).toBe(true);
  });

  it('skips gitignored files and honours a deeper !re-include', () => {
    writeFileSync(join(root, '.gitignore'), 'scratch/\n*.log\n');
    write('scratch/notes.ts');
    write('debug.log');
    write('src/keep.ts');
    mkdirSync(join(root, 'logs'), { recursive: true });
    writeFileSync(join(root, 'logs', '.gitignore'), '!important.log\n');
    write('logs/important.log');
    const paths = resolveProjectFiles(root)?.files.map((f) => f.path);
    expect(paths).toContain('src/keep.ts');
    expect(paths).toContain('logs/important.log');
    expect(paths).not.toContain('scratch/notes.ts');
    expect(paths).not.toContain('debug.log');
  });

  it('never descends into .git or dependency/build trees', () => {
    write('node_modules/pkg/index.js');
    write('dist/bundle.js');
    write('src/app.ts');
    const paths = resolveProjectFiles(root)?.files.map((f) => f.path);
    expect(paths).toEqual(['src/app.ts']);
  });

  it('skips nested checkouts (a subdirectory with its own .git)', () => {
    write('src/app.ts');
    write('.claude/worktrees/wt-x/stolen.ts');
    writeFileSync(join(root, '.claude', 'worktrees', 'wt-x', '.git'), 'gitdir: elsewhere\n');
    write('vendor-clone/inner.ts');
    mkdirSync(join(root, 'vendor-clone', '.git'), { recursive: true });
    const paths = resolveProjectFiles(root)?.files.map((f) => f.path);
    expect(paths).toEqual(['src/app.ts']);
  });

  it('classifies origins by path heuristics', () => {
    write('src/app.ts');
    write('pnpm-lock.yaml');
    write('docs/guide.md');
    write('package.json');
    write('ci.yml');
    write('vendor/lib.js');
    write('test/fixtures/case.json');
    write('data/rows.csv');
    const byPath = new Map(resolveProjectFiles(root)?.files.map((f) => [f.path, f.origin]));
    expect(byPath.get('src/app.ts')).toBe('source');
    expect(byPath.get('pnpm-lock.yaml')).toBe('generated');
    expect(byPath.get('docs/guide.md')).toBe('docs');
    expect(byPath.get('package.json')).toBe('config');
    expect(byPath.get('ci.yml')).toBe('config');
    expect(byPath.get('vendor/lib.js')).toBe('vendored');
    expect(byPath.get('test/fixtures/case.json')).toBe('data');
    expect(byPath.get('data/rows.csv')).toBe('data');
  });
});
