/**
 * A disposable `~/.aka` for one test: the mkdtemp + openLocalDatabase + cleanup
 * sequence that store tests across the workspace repeat, in one place.
 *
 * The temp tree mirrors the real home — `settings/` and `data/` under a base,
 * with the paths resolved through local-layout.ts rather than re-joined here —
 * so a test that touches settings.json or the fingerprint key sees the same
 * shape the product does, and a layout change moves the helper with it.
 *
 * Handles opened through `open()` are closed at teardown, so a test never has
 * to pair an open with a close. `openLocalDatabase` has no memoization: every
 * call re-runs migrations and reseeds default policies, so each `open()` is an
 * independent connection on the one file — which is what makes two live
 * writers, and the contention between them, reachable from a test.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { openLocalDatabase } from '../../src/database.ts';
import { dataDir, dbPath, settingsDir } from '../../src/local-layout.ts';
import { DATA_DIR_MODE } from '../../src/paths.ts';

export interface TempStore {
  /** The mkdtemp root, standing in for `~/.aka`. */
  readonly home: string;
  /** `<home>/settings` — where settings.json lives. */
  readonly settingsDir: string;
  /** `<home>/data` — where aka.db and its -wal/-shm sidecars live. */
  readonly dataDir: string;
  /** `<home>/data/aka.db`. */
  readonly dbFile: string;
  /**
   * A fresh `LocalDatabase` on this store, closed for you at teardown. Call it
   * more than once for independent handles on the same file.
   */
  readonly open: () => LocalDatabase;
  /**
   * Run `fn` before the temp tree is removed, most recent first. Fault
   * injectors take this as their `onCleanup` option — a read-only tree cannot
   * be deleted and a held lock cannot be, either on Windows, so both have to
   * be undone before the rm. Declared as a property, not a method, so it can
   * be handed to an injector without binding.
   */
  readonly onCleanup: (fn: () => void) => void;
}

/** A `TempStore` whose lifetime the caller owns. */
export interface OwnedTempStore extends TempStore {
  /** Run the cleanups, close every handle, remove the tree. Idempotent. */
  readonly destroy: () => void;
}

/**
 * A temp store the caller destroys by hand. Prefer `withTempStore` (scoped) or
 * `useTempStore` (hook-driven); reach for this only when neither shape fits.
 */
export function createTempStore(prefix = 'aka-temp-store-'): OwnedTempStore {
  const home = mkdtempSync(join(tmpdir(), prefix));
  // `data/` is created by openLocalDatabase, but nothing creates `settings/`
  // until a settings writer runs — so a test that writes settings.json by hand
  // would meet an absent directory. Both subdirs exist from the start instead.
  mkdirSync(settingsDir(home), { recursive: true, mode: DATA_DIR_MODE });
  const handles: LocalDatabase[] = [];
  const cleanups: (() => void)[] = [];
  let destroyed = false;

  return {
    home,
    settingsDir: settingsDir(home),
    dataDir: dataDir(home),
    dbFile: dbPath(home),
    open(): LocalDatabase {
      const db = openLocalDatabase(dataDir(home));
      handles.push(db);
      return db;
    },
    onCleanup(fn: () => void): void {
      cleanups.push(fn);
    },
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      // Restores run before the handles close: a cleanup may need to widen a
      // mode the test tightened, and it must run whether or not the test threw.
      for (const fn of cleanups.reverse()) {
        try {
          fn();
        } catch {
          // A cleanup that cannot run must not strand the temp tree.
        }
      }
      for (const db of handles) {
        try {
          db.close();
        } catch {
          // node:sqlite throws on a second close, and a test is free to close a
          // handle itself — an already-closed handle is the expected case here.
        }
      }
      removeTree(home);
    },
  };
}

// Windows refuses to delete a file some handle still has open, where POSIX is
// happy to. A fault test reaches that state legitimately: `openLocalDatabase`
// never closes its `DatabaseSync` when it throws partway through — on a corrupt
// or locked store it fails after construction and the handle is unreachable —
// so nothing can close it before the rm.
//
// Retry through the case where a handle is merely on its way out, then, on
// Windows only, give the tree to the OS temp sweeper rather than fail a test
// whose assertions already passed. POSIX keeps throwing: there the same codes
// mean a cleanup did not run — a forgotten mode restore, say — and that is a
// defect in the test, not the platform.
const STILL_HELD = new Set(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY']);

function removeTree(home: string): void {
  try {
    rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (process.platform !== 'win32' || code === undefined || !STILL_HELD.has(code)) throw err;
  }
}

/** True for anything with a callable `then` — a promise, or a promise-alike. */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

/**
 * Run `fn` against a temp store, then tear it down — including when `fn`
 * throws. The scoped shape: use it where the store's lifetime is one test body
 * or one block, and `useTempStore` where a suite shares setup across hooks.
 *
 * An async `fn` is awaited before teardown. A plain `try/finally` would destroy
 * the store the moment the body returned its pending promise, and the rest of
 * the body would then run against closed handles and a deleted tree — green,
 * and asserting nothing.
 */
export function withTempStore<T>(fn: (store: TempStore) => T, prefix?: string): T {
  const store = createTempStore(prefix);
  let result: T;
  try {
    result = fn(store);
  } catch (err) {
    store.destroy();
    throw err;
  }
  if (!isThenable(result)) {
    store.destroy();
    return result;
  }
  const settled = result.then(
    (value) => {
      store.destroy();
      return value;
    },
    (err: unknown) => {
      store.destroy();
      throw err;
    },
  );
  return settled as T;
}

/**
 * A per-test temp store wired to the suite's own hooks: call it at module (or
 * describe) scope and read the returned store inside tests and hooks. The
 * store's `beforeEach` is registered where this is called, so it runs before
 * any hook the suite declares afterwards, and its teardown runs after theirs.
 *
 * That ordering is `sequence.hooks: 'stack'`, which vitest.config.ts pins
 * rather than inherit: under `'list'` or `'parallel'` the store would be
 * destroyed before a suite's own `afterEach`, and a suite that reads the store
 * in teardown would break with no compile-time signal.
 */
export function useTempStore(prefix?: string): TempStore {
  let current: OwnedTempStore | undefined;

  beforeEach(() => {
    current = createTempStore(prefix);
  });

  afterEach(() => {
    current?.destroy();
    current = undefined;
  });

  const active = (): OwnedTempStore => {
    if (!current) {
      throw new Error(
        'useTempStore(): no store for the current test — call useTempStore() at module or describe scope, not inside a test.',
      );
    }
    return current;
  };

  return {
    get home(): string {
      return active().home;
    },
    get settingsDir(): string {
      return active().settingsDir;
    },
    get dataDir(): string {
      return active().dataDir;
    },
    get dbFile(): string {
      return active().dbFile;
    },
    open: () => active().open(),
    onCleanup: (fn: () => void) => {
      active().onCleanup(fn);
    },
  };
}
