import { chmodSync, existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

import { afterEach, describe, expect, it } from 'vitest';

import { errorFrom } from './errors.ts';
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
    // removeTree never swallows, so past this point a surviving tree means the
    // rm threw and destroy() with it. A root process writes through the mode,
    // leaving nothing to assert.
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

  // The tolerance this replaces existed for a bug that is fixed: the open path
  // used to strand its handle on a throw, so on Windows the tree could not be
  // removed through no fault of the test. Now an undeletable tree is reported on
  // every platform — which is what makes teardown the Windows-side regression
  // signal for that fix, rather than a warning nobody sees.
  it('reports an undeletable tree instead of leaving it to the OS sweeper', (ctx) => {
    if (process.platform === 'win32') ctx.skip('chmod is a no-op for directories on Windows');
    const store = createTempStore();
    mkdirSync(join(store.home, 'locked'));
    chmodSync(store.home, 0o500);

    const err = errorFrom(() => {
      store.destroy();
    });

    // Restore before asserting, so a failed expectation still leaves a tree the
    // runner can clean up.
    chmodSync(store.home, 0o700);
    rmSync(store.home, { recursive: true, force: true });

    // A root process writes through the mode, leaving nothing to assert.
    if (err === undefined) ctx.skip(MODES_IGNORED);

    // Say what it IS before saying what it omits: an AggregateError that named
    // some other failure would satisfy a bare "it threw" check.
    expect(err).toBeInstanceOf(AggregateError);
    const [first] = (err as AggregateError).errors as (Error | undefined)[];
    expect(first).toBeDefined();
    expect(first?.message).toContain(store.home);
    // Naming the tree does NOT discriminate on its own — an unwrapped errno from
    // `rmSync` reads `EACCES: permission denied, rmdir '<home>'` and contains it
    // too. These two are what separate the wrapper from the bare throw: the
    // explanation a reader can act on, and the errno still travelling under it.
    expect(first?.message).toMatch(/still holds a file/);
    expect((first?.cause as { code?: string } | undefined)?.code).toBeTruthy();
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

  it('removes the tree when a cleanup throws, and still reports the failure', () => {
    let home = '';
    let caught: unknown;
    try {
      withTempStore((store) => {
        home = store.home;
        store.onCleanup(() => {
          throw new Error('cleanup failed');
        });
      });
    } catch (err) {
      caught = err;
    }
    // The tree still goes — a cleanup that cannot run must not strand it.
    expect(existsSync(home)).toBe(false);
    // But it is no longer discarded. Swallowing here is how an injector's own
    // loud failure went silent: `lockStore` and `readOnlyStore` both recommend
    // `onCleanup` as the wiring, so a throw from either landed in a bare catch.
    expect(caught).toBeInstanceOf(AggregateError);
    expect((caught as AggregateError).errors[0]).toMatchObject({ message: 'cleanup failed' });
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
