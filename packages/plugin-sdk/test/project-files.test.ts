import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveProjectFiles } from '../src/project-files.ts';

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

  it('classifies manifest-style .txt files as config, not docs', () => {
    write('requirements.txt');
    write('requirements-dev.txt');
    write('CMakeLists.txt');
    write('robots.txt');
    write('notes.txt');
    const byPath = new Map(resolveProjectFiles(root)?.files.map((f) => [f.path, f.origin]));
    expect(byPath.get('requirements.txt')).toBe('config');
    expect(byPath.get('requirements-dev.txt')).toBe('config');
    expect(byPath.get('CMakeLists.txt')).toBe('config');
    expect(byPath.get('robots.txt')).toBe('config');
    expect(byPath.get('notes.txt')).toBe('docs'); // the blanket .txt rule still holds
  });

  // chmod 0o000 is a no-op for root and not a POSIX permission model on Windows.
  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'marks the scan truncated when a subdirectory is unreadable (the prune must be skipped)',
    () => {
      write('src/app.ts');
      write('src/private/hidden.ts');
      chmodSync(join(root, 'src', 'private'), 0o000);
      try {
        const scan = resolveProjectFiles(root);
        expect(scan?.files.map((f) => f.path)).toEqual(['src/app.ts']);
        expect(scan?.truncated).toBe(true);
      } finally {
        chmodSync(join(root, 'src', 'private'), 0o755);
      }
    },
  );

  it('marks a linked-worktree checkout scan truncated (a branch view must never prune the head tree)', () => {
    // The worktree the way git lays it out, under the parent repo at `root`.
    const gitdir = join(root, '.git', 'worktrees', 'wt');
    mkdirSync(gitdir, { recursive: true });
    writeFileSync(join(gitdir, 'commondir'), '../..\n');
    const wt = join(root, '.claude', 'worktrees', 'wt');
    mkdirSync(wt, { recursive: true });
    writeFileSync(join(wt, '.git'), `gitdir: ${gitdir}\n`);
    writeFileSync(join(wt, 'branch-only.ts'), '');

    const scan = resolveProjectFiles(wt);
    expect(scan?.files.map((f) => f.path)).toEqual(['branch-only.ts']);
    expect(scan?.truncated).toBe(true);
  });
});
