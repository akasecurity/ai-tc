import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { walkSourceFiles } from './walk.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-walk-test-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function write(rel: string, content = 'x'): void {
  const full = join(tmp, rel);
  mkdirSync(full.slice(0, full.lastIndexOf('/')), { recursive: true });
  writeFileSync(full, content);
}

describe('walkSourceFiles', () => {
  it('yields source files with correct metadata', () => {
    write('src/app.ts', 'const x = 1;');
    write('src/main.py', 'print("hi")');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    const names = files.map((f) => f.relativePath).sort();
    expect(names).toEqual(['src/app.ts', 'src/main.py']);

    const ts = files.find((f) => f.relativePath === 'src/app.ts');
    expect(ts).toBeDefined();
    expect(ts?.content).toBe('const x = 1;');
    expect(ts?.path).toBe(join(tmp, 'src/app.ts'));
    expect(ts?.mtime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('skips non-source extensions', () => {
    write('README.md');
    write('image.png');
    write('data.json');
    write('app.ts');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['app.ts']);
  });

  it('skips node_modules and other skip-listed directories', () => {
    write('node_modules/lodash/index.js');
    write('.git/config');
    write('dist/bundle.js');
    write('src/app.ts');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
  });

  it('skips files over maxFileSizeBytes', () => {
    write('big.ts', 'x'.repeat(600 * 1024)); // 600 KB
    write('small.ts', 'const x = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['small.ts']);
  });

  it('respects custom extensions', () => {
    write('app.ts');
    write('app.py');
    write('app.rb');

    const files = [...walkSourceFiles({ rootDir: tmp, extensions: new Set(['.rb']) })];
    expect(files.map((f) => f.relativePath)).toEqual(['app.rb']);
  });

  it('returns empty on empty directory', () => {
    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files).toHaveLength(0);
  });

  it('returns empty on nonexistent directory', () => {
    const files = [...walkSourceFiles({ rootDir: join(tmp, 'does-not-exist') })];
    expect(files).toHaveLength(0);
  });
});
