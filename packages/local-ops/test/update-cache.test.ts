import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir } from '@akasecurity/persistence';
import type { UpdateCache } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { cachePath, readCache, writeCache } from '../src/update-cache.ts';

// update-check.json lives in ~/.aka/data alongside the store, so it is held to the
// same owner-only mode as everything else there. It was the one file in that
// directory nothing tightened: a bare writeFileSync left it at the caller's umask,
// and `aka init` then reported it as a store path whose chmod the filesystem had
// rejected — a diagnosis with no rejected chmod behind it.

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-update-cache-'));
  mkdirSync(dataDir(home), { recursive: true });
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const cache = (): UpdateCache => ({
  checkedAt: 1_700_000_000_000,
  report: { statuses: [], availablePlugins: [] },
  notifiedPluginIds: [],
});

describe('writeCache', () => {
  it('lands the cache owner-only (0600), not at the caller’s umask', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    writeCache(home, cache());

    expect(statSync(cachePath(home)).mode & 0o777).toBe(0o600);
  });

  it('rewrites an existing loose cache to 0600 rather than preserving its mode', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    // The upgrade path: a cache an older build left at 0644 is replaced, not
    // written through. The writer renames a fresh owner-only inode over it, so the
    // next refresh self-heals a file this build inherited loose.
    writeCache(home, cache());
    chmodSync(cachePath(home), 0o644);
    expect(statSync(cachePath(home)).mode & 0o777).toBe(0o644); // precondition

    writeCache(home, { ...cache(), checkedAt: 1_700_000_001_000 });

    expect(statSync(cachePath(home)).mode & 0o777).toBe(0o600);
  });

  it('round-trips through readCache and leaves no tmp behind', () => {
    writeCache(home, cache());

    expect(readCache(home)?.checkedAt).toBe(1_700_000_000_000);
    expect(readdirSync(dataDir(home)).filter((f) => f.includes('.tmp'))).toEqual([]);
    expect(readFileSync(cachePath(home), 'utf8').endsWith('\n')).toBe(true);
  });

  it('never provisions the store dir when the user has not run `aka init`', () => {
    // A passive update check must not create ~/.aka behind the user's back, so an
    // absent data dir is a silent no-op rather than a mkdir.
    const fresh = mkdtempSync(join(tmpdir(), 'aka-uninitialized-'));
    try {
      writeCache(fresh, cache());
      expect(existsSync(dataDir(fresh))).toBe(false);
      expect(existsSync(cachePath(fresh))).toBe(false);
    } finally {
      rmSync(fresh, { recursive: true, force: true });
    }
  });
});
