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

describe('walkSourceFiles — shouldRead', () => {
  it('consults shouldRead with stat metadata before reading, and skips on false', () => {
    write('src/skip.ts', 'const skipped = 1;');
    write('src/keep.ts', 'const kept = 1;');

    const seen: string[] = [];
    const files = [
      ...walkSourceFiles({
        rootDir: tmp,
        shouldRead: (meta) => {
          seen.push(meta.relativePath);
          expect(meta.size).toBeGreaterThan(0);
          expect(meta.mtime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
          return meta.relativePath !== 'src/skip.ts';
        },
      }),
    ];

    expect(seen.sort()).toEqual(['src/keep.ts', 'src/skip.ts']);
    expect(files.map((f) => f.relativePath)).toEqual(['src/keep.ts']);
  });
});

describe('walkSourceFiles — .gitignore marking (never skipping)', () => {
  it('yields gitignored files with gitignored: true and tracked files with false', () => {
    write('.gitignore', 'scratch.ts\n');
    write('scratch.ts', 'const local = 1;');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    const byPath = new Map(files.map((f) => [f.relativePath, f.gitignored]));
    expect(byPath.get('scratch.ts')).toBe(true);
    expect(byPath.get('src/app.ts')).toBe(false);
    // Marked, not skipped: the gitignored file is still read and yielded.
    expect(files.find((f) => f.relativePath === 'scratch.ts')?.content).toBe('const local = 1;');
  });

  it('marks everything under a gitignored directory', () => {
    write('.gitignore', 'generated/\n');
    write('generated/deep/code.ts', 'const gen = 1;');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.find((f) => f.relativePath === 'generated/deep/code.ts')?.gitignored).toBe(true);
    expect(files.find((f) => f.relativePath === 'src/app.ts')?.gitignored).toBe(false);
  });

  it('honors nested .gitignore files and negation re-includes', () => {
    write('.gitignore', '*.gen.ts\n');
    write('src/.gitignore', '!keep.gen.ts\n');
    write('src/keep.gen.ts', 'const kept = 1;');
    write('src/other.gen.ts', 'const dropped = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.find((f) => f.relativePath === 'src/keep.gen.ts')?.gitignored).toBe(false);
    expect(files.find((f) => f.relativePath === 'src/other.gen.ts')?.gitignored).toBe(true);
  });

  it('marks nothing when there is no .gitignore', () => {
    write('src/app.ts', 'const app = 1;');
    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.every((f) => !f.gitignored)).toBe(true);
  });

  it('exposes gitignored on shouldRead metadata', () => {
    write('.gitignore', 'scratch.ts\n');
    write('scratch.ts', 'const local = 1;');

    const seen: boolean[] = [];
    const files = [
      ...walkSourceFiles({
        rootDir: tmp,
        shouldRead: (meta) => {
          seen.push(meta.gitignored);
          return true;
        },
      }),
    ];
    expect(seen).toEqual([true]);
    expect(files).toHaveLength(1);
  });
});

describe('walkSourceFiles — .akaignore (hard skip) and SKIP_DIRS override', () => {
  it('hard-skips .akaignore matches: never yielded, never offered to shouldRead', () => {
    write('.akaignore', 'excluded.ts\n');
    write('excluded.ts', 'const hidden = 1;');
    write('src/app.ts', 'const app = 1;');

    const offered: string[] = [];
    const files = [
      ...walkSourceFiles({
        rootDir: tmp,
        shouldRead: (meta) => {
          offered.push(meta.relativePath);
          return true;
        },
      }),
    ];

    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
    // Skipped before the pre-read gate — the file costs nothing.
    expect(offered).toEqual(['src/app.ts']);
  });

  it('hard-skips whole directories via .akaignore', () => {
    write('.akaignore', 'fixtures/\n');
    write('fixtures/sample.ts', 'const fixture = 1;');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
  });

  it('a .akaignore negation re-includes a SKIP_DIRS directory (first-party vendor/)', () => {
    write('.akaignore', '!vendor/\n');
    write('vendor/firstparty.ts', 'const ours = 1;');
    write('node_modules/dep/index.js', 'module.exports = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['vendor/firstparty.ts']);
  });

  it('SKIP_DIRS still applies without a negation', () => {
    write('vendor/lib.ts', 'const theirs = 1;');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
  });

  it('.gitignore marks while .akaignore skips in the same tree', () => {
    write('.gitignore', 'scratch.ts\n');
    write('.akaignore', 'excluded.ts\n');
    write('scratch.ts', 'const marked = 1;');
    write('excluded.ts', 'const skipped = 1;');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    const names = files.map((f) => f.relativePath).sort();
    expect(names).toEqual(['scratch.ts', 'src/app.ts']);
    expect(files.find((f) => f.relativePath === 'scratch.ts')?.gitignored).toBe(true);
  });

  it('honors nested .akaignore files with negation re-includes', () => {
    write('.akaignore', '*.tmp.ts\n');
    write('src/.akaignore', '!keep.tmp.ts\n');
    write('src/keep.tmp.ts', 'const kept = 1;');
    write('src/drop.tmp.ts', 'const dropped = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/keep.tmp.ts']);
  });
});

describe('walkSourceFiles — excludePatterns', () => {
  it('prunes files and directories using gitignore syntax anchored at rootDir', () => {
    write('legacy/old.ts', 'const old = 1;');
    write('src/app.ts', 'const app = 1;');
    write('src/app.spec.ts', 'const spec = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp, excludePatterns: ['legacy/', '*.spec.ts'] })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
  });

  it('on-disk .akaignore negations override host excludePatterns', () => {
    write('.akaignore', '!important.ts\n');
    write('important.ts', 'const keep = 1;');
    write('other.ts', 'const drop = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp, excludePatterns: ['*.ts'] })];
    expect(files.map((f) => f.relativePath)).toEqual(['important.ts']);
  });
});

describe('walkSourceFiles — extension parsing edge cases', () => {
  it('skips extension-less names and dotfiles rather than misparsing them', () => {
    write('Makefile', 'all: build');
    write('.eslintrc', '{}');
    write('src/app.ts', 'const app = 1;');

    const files = [...walkSourceFiles({ rootDir: tmp })];
    expect(files.map((f) => f.relativePath)).toEqual(['src/app.ts']);
  });
});
