import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  dataDir,
  dbPath,
  ensureLayoutDirSync,
  migrateLegacyLayout,
  settingsDir,
} from '../src/local-layout.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-datadir-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('layout helpers', () => {
  it('compose settings/, data/, and the db path from a base', () => {
    expect(settingsDir(base)).toBe(join(base, 'settings'));
    expect(dataDir(base)).toBe(join(base, 'data'));
    expect(dbPath(base)).toBe(join(base, 'data', 'aka.db'));
  });
});

describe('ensureLayoutDirSync', () => {
  it('creates the directory owner-only (0700) where POSIX modes apply', () => {
    const dir = dataDir(base);
    ensureLayoutDirSync(dir);
    expect(existsSync(dir)).toBe(true);
    if (process.platform === 'win32') return;
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });
});

describe('migrateLegacyLayout', () => {
  it('routes pre-layout flat files to their layout subdirs (best-effort)', () => {
    writeFileSync(join(base, 'config.json'), '{"backendUrl":"https://x","token":"t"}');
    writeFileSync(join(base, 'policy-cache.json'), '{"bundle":{}}');

    migrateLegacyLayout(base);

    expect(existsSync(join(base, 'config.json'))).toBe(false);
    expect(existsSync(join(base, 'policy-cache.json'))).toBe(false);
    // config.json is settings; policy-cache.json is a cache that lives with the
    // SQLite store under data/.
    expect(readFileSync(join(settingsDir(base), 'config.json'), 'utf8')).toContain('backendUrl');
    expect(existsSync(join(dataDir(base), 'policy-cache.json'))).toBe(true);
  });

  it('is a no-op when there is nothing to migrate', () => {
    expect(() => {
      migrateLegacyLayout(base);
    }).not.toThrow();
  });
});
