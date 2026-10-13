import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  canonicalizeScanPath,
  isProtectedScanPath,
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
    ['.env', 'secret-bearing'],
    ['.env.local', 'secret-bearing'],
    ['.env.production', 'secret-bearing'],
    ['.env.example', 'secret-bearing'],
    ['README.md', 'other'],
    ['Makefile', 'other'],
    ['.eslintrc', 'other'],
    ['.envrc', 'other'],
    ['env', 'other'],
  ])('classifies %s as %s', (name, kind) => {
    expect(scanFileKind(name)).toBe(kind);
  });

  it('classifies by the given source extensions when they are supplied', () => {
    const rubyOnly = new Set(['.rb']);
    expect(scanFileKind('app.rb', rubyOnly)).toBe('source');
    expect(scanFileKind('index.ts', rubyOnly)).toBe('other');
    expect(scanFileKind('.env', rubyOnly)).toBe('secret-bearing');
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

  it('names the host credentials and both AKA homes under the given bases', () => {
    const akaHome = join(home, 'relocated-aka');
    const roots = protectedScanRoots(home, akaHome);
    expect(roots).toEqual(
      expect.arrayContaining([
        resolve(home, '.claude', 'ide'),
        resolve(home, '.claude', '.credentials.json'),
        resolve(home, '.codex', 'auth.json'),
        resolve(akaHome),
        resolve(home, '.aka'),
      ]),
    );
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

  it('canonicalizes an existing path through symlinks and leaves an absent one lexical', () => {
    const real = join(home, 'real');
    mkdirSync(real);
    writeFileSync(join(real, 'f.txt'), 'x');
    const link = join(home, 'link');
    symlinkSync(real, link);
    expect(canonicalizeScanPath(join(link, 'f.txt'))).toBe(
      canonicalizeScanPath(join(real, 'f.txt')),
    );
    expect(canonicalizeScanPath(join(home, 'missing', '..', 'absent'))).toBe(
      resolve(home, 'absent'),
    );
  });
});
