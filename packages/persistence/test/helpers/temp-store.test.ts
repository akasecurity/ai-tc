import { chmodSync, existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

import { afterEach, describe, expect, it } from 'vitest';

import { createTempStore, useTempStore, withTempStore } from './temp-store.ts';

// The helper's own gate: every store test that adopts it inherits these
// guarantees, so a regression here is a regression in all of them.

const MODES_IGNORED =
  'this host ignores the mode change — a root process, or a filesystem without POSIX modes';

describe('withTempStore', () => {
  it('lays the temp tree out like the real home', () => {
    withTempStore((store) => {
      expect(store.settingsDir).toBe(join(store.home, 'settings'));
      expect(store.dataDir).toBe(join(store.home, 'data'));
      expect(store.dbFile).toBe(join(store.home, 'data', 'aka.db'));
      // Both exist from the start. `data/` would otherwise appear only on the
      // first open(), and settings/ not until a settings writer ran — a test
      // seeding either by hand should not have to know that.
      expect({
        settings: existsSync(store.settingsDir),
        data: existsSync(store.dataDir),
      }).toEqual({ settings: true, data: true });
    });
  });

  it('hands out raw handles that close themselves at teardown', () => {
    let home = '';
    let raw: DatabaseSync | undefined;
    withTempStore((store) => {
      home = store.home;
      raw = store.openRaw();
      raw.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
      expect(raw.isOpen).toBe(true);
      // Deliberately not closed: a test that fails mid-body never reaches its
      // own close, which is where Windows then refuses to delete the tree.
    });
    expect(raw?.isOpen).toBe(false);
    expect(existsSync(home)).toBe(false);
  });

  it('counts the handles that are still open, however they were opened', () => {
    withTempStore((store) => {
      expect(store.openHandleCount()).toBe(0);

      const db = store.open();
      const raw = store.openRaw();
      expect(store.openHandleCount()).toBe(2);

      // A close the test performs itself counts, not just teardown's.
      db.close();
      expect(store.openHandleCount()).toBe(1);
      raw.close();
      expect(store.openHandleCount()).toBe(0);
    });
  });

  // The teardown failure this forces is a mode `removeTree` cannot delete
  // through, so the whole case rests on the mode biting. On Windows a
  // directory's mode is ignored, `removeTree` succeeds, and there is no
  // teardown failure left to assert.
  it('keeps a failing teardown from speaking over the body failure', (ctx) => {
    if (process.platform === 'win32') ctx.skip('chmod is a no-op for directories on Windows');
    let home = '';
    let caught: Error | undefined;
    try {
      withTempStore((store) => {
        home = store.home;
        // A mode the test never restores: removeTree rethrows on POSIX, which
        // must not replace the assertion that actually broke.
        mkdirSync(join(store.home, 'locked'));
        chmodSync(store.home, 0o500);
        throw new Error('THE-REAL-FAILURE');
      });
    } catch (err) {
      caught = err as Error;
    }
    // removeTree only ever swallows on Windows, which is already skipped above,
    // so past this point a surviving tree means the rm threw and destroy() with
    // it. A root process writes through the mode, leaving nothing to assert.
    const teardownFailed = existsSync(home);
    if (teardownFailed) {
      chmodSync(home, 0o700);
      rmSync(home, { recursive: true, force: true });
    }
    if (!teardownFailed) ctx.skip(MODES_IGNORED);

    expect(caught?.message).toBe('THE-REAL-FAILURE');
    // The teardown failure is not dropped either — it travels as the cause.
    expect(caught?.cause).toBeDefined();
  });

  it('opens a usable store under data/', () => {
    withTempStore((store) => {
      const db = store.open();
      db.ruleProbeCache.setVerdict('rule-a', 'safe', 1.5);
      expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({
        verdict: 'safe',
        worstProbeMs: 1.5,
      });
      expect(existsSync(store.dbFile)).toBe(true);
      expect(dirname(store.dbFile)).toBe(store.dataDir);
    });
  });

  it('closes its handles and removes the tree when the body returns', () => {
    let home = '';
    withTempStore((store) => {
      home = store.home;
      store.open();
      store.open();
    });
    expect(existsSync(home)).toBe(false);
  });

  it('removes the tree when the body throws, and rethrows', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.open();
        throw new Error('boom');
      });
    }).toThrow('boom');
    expect(home).not.toBe('');
    expect(existsSync(home)).toBe(false);
  });

  it('tolerates a handle the body closed itself', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.open().close();
      });
    }).not.toThrow();
    expect(existsSync(home)).toBe(false);
  });

  it('opens independent handles that see one another writes', () => {
    withTempStore((store) => {
      const a = store.open();
      const b = store.open();
      expect(a).not.toBe(b);
      a.ruleProbeCache.setVerdict('shared', 'quarantined', 250);
      expect(b.ruleProbeCache.getVerdict('shared')).toEqual({
        verdict: 'quarantined',
        worstProbeMs: 250,
      });
    });
  });

  it('runs cleanups most-recent-first, while the tree still exists', () => {
    const order: string[] = [];
    let seen = false;
    let home = '';
    withTempStore((store) => {
      home = store.home;
      store.onCleanup(() => {
        order.push('first');
        seen = existsSync(store.home);
      });
      store.onCleanup(() => {
        order.push('second');
      });
    });
    expect(order).toEqual(['second', 'first']);
    expect(seen).toBe(true);
    expect(existsSync(home)).toBe(false);
  });

  it('keeps a cleanup that throws from stranding the tree', () => {
    let home = '';
    expect(() => {
      withTempStore((store) => {
        home = store.home;
        store.onCleanup(() => {
          throw new Error('cleanup failed');
        });
      });
    }).not.toThrow();
    expect(existsSync(home)).toBe(false);
  });

  it('honours a caller-supplied temp-dir prefix', () => {
    withTempStore((store) => {
      expect(basename(store.home).startsWith('aka-custom-prefix-')).toBe(true);
    }, 'aka-custom-prefix-');
  });

  // A `try/finally` would destroy the store the moment an async body returned
  // its pending promise, and everything after the first await would run against
  // closed handles and a deleted tree — passing, and asserting nothing.
  it('waits for an async body before tearing down', async () => {
    let home = '';
    await withTempStore(async (store) => {
      home = store.home;
      const db = store.open();
      await Promise.resolve();
      db.ruleProbeCache.setVerdict('after-await', 'safe', 3);
      expect(db.ruleProbeCache.getVerdict('after-await')).toEqual({
        verdict: 'safe',
        worstProbeMs: 3,
      });
      expect(existsSync(store.dbFile)).toBe(true);
    });
    expect(existsSync(home)).toBe(false);
  });

  it('removes the tree when an async body rejects, and rethrows', async () => {
    let home = '';
    await expect(
      withTempStore(async (store) => {
        home = store.home;
        store.open();
        await Promise.resolve();
        throw new Error('async boom');
      }),
    ).rejects.toThrow('async boom');
    expect(existsSync(home)).toBe(false);
  });
});

describe('createTempStore', () => {
  it('destroys once, however many times it is asked', () => {
    const store = createTempStore();
    store.open();
    store.destroy();
    expect(existsSync(store.home)).toBe(false);
    expect(() => {
      store.destroy();
    }).not.toThrow();
  });

  it('creates the data dir owner-only where modes apply', (ctx) => {
    if (process.platform === 'win32') ctx.skip('chmod is a no-op for directories on Windows');
    withTempStore((store) => {
      store.open();
      expect(statSync(store.dataDir).mode & 0o777).toBe(0o700);
      expect(statSync(store.settingsDir).mode & 0o777).toBe(0o700);
    });
  });
});

describe('useTempStore', () => {
  const store = useTempStore('aka-use-temp-store-');
  let firstHome = '';

  it('hands the first test an empty store', () => {
    firstHome = store.home;
    expect(store.open().ruleProbeCache.getVerdict('carried-over')).toBeUndefined();
    store.open().ruleProbeCache.setVerdict('carried-over', 'safe', 1);
  });

  it('hands the next test a different, equally empty store', () => {
    expect(store.home).not.toBe(firstHome);
    expect(existsSync(firstHome)).toBe(false);
    expect(store.open().ruleProbeCache.getVerdict('carried-over')).toBeUndefined();
  });
});

// The guard behind vitest.config.ts's `sequence.hooks: 'stack'`. Without it the
// pin can be deleted, inverted, or lost to a vitest upgrade and nothing notices
// until someone writes the first teardown that reads the store — where it
// arrives as a use-after-destroy rather than as "the hook order changed".
describe('useTempStore teardown ordering', () => {
  const store = useTempStore('aka-hook-order-');
  let dbFile = '';
  let aliveInTeardown: boolean | undefined;

  // Registered after useTempStore's own afterEach. Only 'stack' runs "after"
  // hooks in reverse, which is what puts this one first, while the store is
  // still standing; 'list' and 'parallel' destroy it before this runs.
  afterEach(() => {
    // The path is captured in the test body, not read from the store here:
    // after a destroy, `store.dbFile` throws rather than returning a stale
    // path, and this has to fail as a plain assertion, not a hook exception.
    aliveInTeardown = existsSync(dbFile);
  });

  it('opens a store the suite teardown can still see', () => {
    dbFile = store.dbFile;
    store.open();
    expect(existsSync(dbFile)).toBe(true);
  });

  it('found the store alive in the previous test teardown', () => {
    expect(aliveInTeardown).toBe(true);
  });
});
