import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse, resolve, sep } from 'node:path';

import { defaultDataDir } from '@akasecurity/persistence/sqlite-free';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  canonicalizeScanPath,
  isProtectedScanPath,
  isSecretBearingFileSnapshot,
  protectedScanRoots,
  scanFileKind,
  SOURCE_EXTENSIONS,
} from '../src/scan-files.ts';

describe('scanFileKind', () => {
  it.each([
    ['index.ts', 'source'],
    ['component.tsx', 'source'],
    ['main.py', 'source'],
    ['handler.go', 'source'],
    ['.env.ts', 'source'],
    ['.env.local.ts', 'source'],
    ['.env', 'secret-bearing'],
    ['.env.local', 'secret-bearing'],
    ['.env.production', 'secret-bearing'],
    ['.env.example', 'secret-bearing'],
    ['.env.sample', 'secret-bearing'],
    ['.env.template', 'secret-bearing'],
    ['.env.dist', 'secret-bearing'],
    ['.envrc', 'secret-bearing'],
    ['.ENV', 'secret-bearing'],
    ['.Env.Local', 'secret-bearing'],
    ['README.md', 'other'],
    ['Makefile', 'other'],
    ['.eslintrc', 'other'],
    ['.environment', 'other'],
    ['foo.env', 'secret-bearing'],
    ['prod.ENV', 'secret-bearing'],
    ['app.env.production', 'secret-bearing'],
    ['config.env.local', 'secret-bearing'],
    ['App.ENV.Production', 'secret-bearing'],
    ['app.env.production.ts', 'source'],
    ['app.environment.local', 'other'],
    ['README.env.md', 'other'],
    ['notes.env.txt', 'other'],
    ['diagram.env.png', 'other'],
    ['.env.production.local', 'secret-bearing'],
    ['app.env.staging', 'secret-bearing'],
    ['env.example', 'other'],
    ['env', 'other'],
  ])('classifies %s as %s', (name, kind) => {
    expect(scanFileKind(name)).toBe(kind);
  });

  it('gives a full path the same answer as its basename', () => {
    expect(scanFileKind(join('repo', 'src', 'index.ts'))).toBe('source');
    expect(scanFileKind(join('repo', '.env'))).toBe('secret-bearing');
    expect(scanFileKind(join('repo', '.env.local'))).toBe('secret-bearing');
    expect(scanFileKind(join('repo', 'README.md'))).toBe('other');
  });

  it('classifies by the given source extensions when they are supplied', () => {
    const rubyOnly = new Set(['.rb']);
    expect(scanFileKind('app.rb', rubyOnly)).toBe('source');
    expect(scanFileKind('index.ts', rubyOnly)).toBe('other');
    expect(scanFileKind('.env', rubyOnly)).toBe('secret-bearing');
    expect(scanFileKind('app.rb', new Set(['rb']))).toBe('other');
  });

  it('exposes the default source extensions', () => {
    expect(SOURCE_EXTENSIONS.has('.ts')).toBe(true);
    expect(SOURCE_EXTENSIONS.has('.md')).toBe(false);
  });
});

describe('protected scan roots', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'scan-files-'));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it('names exactly the host credentials and the AKA homes under the given bases', () => {
    const akaHome = join(home, 'relocated-aka');
    const expected = [
      ...new Set(
        [
          resolve(home, '.claude', 'ide'),
          resolve(home, '.claude', '.credentials.json'),
          resolve(home, '.codex', 'auth.json'),
          resolve(akaHome),
          defaultDataDir(),
          resolve(home, '.aka'),
        ].map(canonicalizeScanPath),
      ),
    ];
    expect([...protectedScanRoots(home, akaHome)].sort()).toEqual(expected.sort());
  });

  it('lists each root once when the AKA homes coincide', () => {
    const roots = protectedScanRoots(home, join(home, '.aka'));
    expect(new Set(roots).size).toBe(roots.length);
  });

  it('protects a root and everything under it, but not a sibling sharing its prefix', () => {
    const roots = protectedScanRoots(home, join(home, '.aka'));
    const auth = resolve(home, '.codex', 'auth.json');
    expect(isProtectedScanPath(auth, roots)).toBe(true);
    expect(isProtectedScanPath(join(resolve(home, '.claude', 'ide'), '1.lock'), roots)).toBe(true);
    expect(isProtectedScanPath(`${auth}.bak`, roots)).toBe(false);
    expect(isProtectedScanPath(resolve(home, 'project', '.env'), roots)).toBe(false);
  });

  it('protects everything under a root that is a filesystem root', () => {
    const fsRoot = parse(resolve(home)).root;
    expect(isProtectedScanPath(resolve(home, 'any', 'file'), [fsRoot])).toBe(true);
    expect(isProtectedScanPath(fsRoot, [fsRoot])).toBe(true);
  });

  it('canonicalizes an existing path through a directory link', (ctx) => {
    const real = join(home, 'real');
    mkdirSync(real);
    writeFileSync(join(real, 'f.txt'), 'x');
    const link = join(home, 'link');
    try {
      symlinkSync(real, link, 'junction');
    } catch (err) {
      ctx.skip(`symlink unavailable on this host: ${(err as Error).message}`);
    }
    expect(canonicalizeScanPath(join(link, 'f.txt'))).toBe(
      canonicalizeScanPath(join(real, 'f.txt')),
    );
  });

  it('leaves an absent path in its lexical form', () => {
    expect(canonicalizeScanPath(`${home}${sep}missing${sep}..${sep}absent`)).toBe(
      resolve(home, 'absent'),
    );
  });

  it('returns the on-disk casing where the volume folds case', (ctx) => {
    const lower = join(home, '.claude', 'ide', '1.lock');
    mkdirSync(join(home, '.claude', 'ide'), { recursive: true });
    writeFileSync(lower, 'x');
    const mixed = join(home, '.claude', 'IDE', '1.lock');
    if (!existsSync(mixed)) ctx.skip('case-sensitive filesystem: ...IDE/ names no file');
    expect(canonicalizeScanPath(mixed)).toBe(canonicalizeScanPath(lower));
    expect(canonicalizeScanPath(mixed).endsWith(join('ide', '1.lock'))).toBe(true);
  });
});

describe('isSecretBearingFileSnapshot', () => {
  it.each([
    [{ filePath: '/repo/.env', wholeFile: true }, true],
    [{ filePath: '/repo/config/.env.local', wholeFile: true }, true],
    [{ filePath: '/repo/.env', wholeFile: false }, false],
    [{ filePath: '/repo/.env' }, false],
    [{ filePath: '/repo/.env.ts', wholeFile: true }, false],
    [{ filePath: '/repo/app.ts', wholeFile: true }, false],
    [{ wholeFile: true }, false],
    [undefined, false],
  ])('%j → %s', (metadata, expected) => {
    expect(isSecretBearingFileSnapshot(metadata)).toBe(expected);
  });
});
