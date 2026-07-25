import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
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

  it('tightens an existing loose base directory to 0700', () => {
    // An ~/.aka created by an older release (or the user) with looser
    // permissions must be tightened, not left as it was found.
    const home = join(base, 'loose-home');
    mkdirSync(home);
    chmodSync(home, 0o755);
    ensureLayoutDirSync(home);
    if (process.platform === 'win32') return;
    expect(statSync(home).mode & 0o777).toBe(0o700);
  });

  it('leaves the whole ~/.aka layout owner-only (0700 base, settings/, data/) — the `aka init` shape', () => {
    // Mirrors what `aka init` composes: ensure the base, then settings/, then
    // data/ (the last via openLocalDatabase). All three are the store's only
    // at-rest control and must all end 0700.
    const home = join(base, 'home');
    ensureLayoutDirSync(home);
    ensureLayoutDirSync(settingsDir(home));
    ensureLayoutDirSync(dataDir(home));
    if (process.platform === 'win32') return;
    expect(statSync(home).mode & 0o777).toBe(0o700);
    expect(statSync(settingsDir(home)).mode & 0o777).toBe(0o700);
    expect(statSync(dataDir(home)).mode & 0o777).toBe(0o700);
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

  it('tightens a pre-existing loose destination dir to 0700 while migrating', () => {
    // A settings/ that already existed with looser permissions must be tightened
    // as the flat config.json is routed into it — it holds sensitive files.
    writeFileSync(join(base, 'config.json'), '{"backendUrl":"https://x","token":"t"}');
    mkdirSync(settingsDir(base));
    chmodSync(settingsDir(base), 0o777);

    migrateLegacyLayout(base);

    expect(existsSync(join(settingsDir(base), 'config.json'))).toBe(true);
    if (process.platform === 'win32') return;
    expect(statSync(settingsDir(base)).mode & 0o777).toBe(0o700);
  });

  it('tightens a moved legacy config.json to 0600 (it can carry a token)', () => {
    // A pre-layout config.json held the backend token; a rename preserves its
    // (possibly loose) mode, so the moved file must be tightened to 0600 too —
    // not left group/other-readable inside settings/.
    const flat = join(base, 'config.json');
    writeFileSync(flat, '{"backendUrl":"https://x","token":"t"}');
    if (process.platform !== 'win32') chmodSync(flat, 0o644);

    migrateLegacyLayout(base);

    const moved = join(settingsDir(base), 'config.json');
    expect(existsSync(moved)).toBe(true);
    if (process.platform === 'win32') return;
    expect(statSync(moved).mode & 0o777).toBe(0o600);
  });
});
