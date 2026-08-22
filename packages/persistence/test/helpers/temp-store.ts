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
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { openLocalDatabase } from '../../src/database.ts';
import { dataDir, dbPath, settingsDir } from '../../src/local-layout.ts';
import { ensureDataDirSync } from '../../src/paths.ts';
import { migratedStore } from './migrated-store.ts';

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
   * A raw `DatabaseSync` on the same file, closed for you at teardown. A test
   * that opens one by hand has to close it on every path, including the one
   * where an assertion just failed — which is where it is most often forgotten,
   * and where Windows then refuses to delete the tree.
   */
  readonly openRaw: () => DatabaseSync;
  /**
   * How many handles handed out by `open`/`openRaw` are still open. Injectors
   * whose precondition is "no live connection" check this rather than trust the
   * caller to have read the doc.
   */
  readonly openHandleCount: () => number;
  /**
   * Run `fn` before the temp tree is removed, most recent first. Fault
   * injectors take this as their `onCleanup` option — a read-only tree cannot
   * be deleted and a held lock cannot be, either on Windows, so both have to
   * be undone before the rm.
   */
  readonly onCleanup: (fn: () => void) => void;
}

/** A `TempStore` whose lifetime the caller owns. */
export interface OwnedTempStore extends TempStore {
  /**
   * Run the cleanups, close every handle, remove the tree. Idempotent.
   *
   * Throws an `AggregateError` if a cleanup or the removal failed — after the
   * tree is gone, so a failure reports rather than strands. On the
   * body-already-failed path `withTempStore` demotes it to that error's
   * `cause`, since the body's failure is the one worth reading.
   */
  readonly destroy: () => void;
}

/** A handle the store handed out, and the two things it needs to track it. */
interface TrackedHandle {
  close: () => void;
  isOpen: () => boolean;
}

/** What a caller can vary about the store it gets. */
export interface TempStoreOptions {
  /**
   * Seed `data/` from the pre-migrated template instead of letting the first
   * `open()` run every migration — the same file each test would have built for
   * itself, built once per worker and copied. Per-test isolation is unchanged:
   * the copy is this store's own file, and no handle is shared.
   *
   * Leave it off for a suite whose SUBJECT is the open path — migrations, the
   * lineage reset, the pre-drop snapshot, or a fault injected so that
   * `applyMigrations` is the thing that refuses. A seeded store has nothing
   * left to migrate, so those assertions would hold vacuously rather than fail.
   *
   * The snapshot case still belongs on that list, but it no longer arrives on
   * its own: a fresh migration leaves a `.bak` only where the legacy drop would
   * destroy rows, so such a suite has to seed legacy history for one to exist
   * at all — and a templated store, whose drop has already run, would never
   * take one however it was seeded.
   */
  readonly migrated?: boolean;
}

/**
 * A temp store the caller destroys by hand. Prefer `withTempStore` (scoped) or
 * `useTempStore` (hook-driven); reach for this only when neither shape fits.
 */
export function createTempStore(
  prefix = 'aka-temp-store-',
  options: TempStoreOptions = {},
): OwnedTempStore {
  const home = mkdtempSync(join(tmpdir(), prefix));
  // Both subdirs up front, through the same helper the product uses: a bare
  // `mkdirSync` mode is umask-masked and is not applied to a directory that
  // already exists, so `ensureDataDirSync`'s follow-up chmod is what makes 0700
  // a guarantee rather than a request. `data/` would otherwise appear only on
  // the first `open()`, and a test seeding the store by hand — a
  // policy-cache.json, a read-only directory — would meet an absent path.
  // Anything that can throw between the mkdtemp and the returned store has to
  // take the tree with it. Nothing here is reachable by `destroy()` yet — the
  // caller has no handle to call it on, and under `useTempStore` a throwing
  // `beforeEach` leaves `current` undefined, so its `afterEach` no-ops and the
  // tree is stranded once per test in the file rather than once.
  try {
    ensureDataDirSync(settingsDir(home));
    ensureDataDirSync(dataDir(home));
    // Before any handle exists, so the first `open()` finds a store with every
    // migration already ledgered and skips the lot.
    if (options.migrated === true) migratedStore.seed(dataDir(home));
  } catch (err) {
    // The setup failure is the one worth reading; a teardown that also fails
    // must not speak over it.
    try {
      removeTree(home);
    } catch {
      // Nothing to add — the original error is already on its way out.
    }
    throw err;
  }

  const handles: TrackedHandle[] = [];
  const cleanups: (() => void)[] = [];
  let destroyed = false;

  // Arrow properties, not method shorthand: these get handed to injectors
  // unbound (`{ onCleanup: store.onCleanup }`), so binding must not matter.
  return {
    home,
    settingsDir: settingsDir(home),
    dataDir: dataDir(home),
    dbFile: dbPath(home),
    open: (): LocalDatabase => {
      const db = openLocalDatabase(dataDir(home));
      // LocalDatabase has no `isOpen`, so the close is wrapped to record it —
      // otherwise a handle a test closed itself still counts as live.
      //
      // The spread below is load-bearing and only safe because
      // `openLocalDatabase` returns a plain object literal of closures: no
      // accessors, nothing `this`-bound, nothing lazily got. Turn that into a
      // class instance or add a getter and every handle handed out here goes
      // quietly wrong instead of failing.
      //
      // It also carries UNSAFE_TEST_ONLY_RAW_HANDLE, which spread copies because
      // that property is an enumerable own symbol. A fault test capping the
      // connection reads it off the wrapper handed back here, so a handle that
      // lost it would leave the cap pointed at nothing and every fault
      // assertion downstream passing vacuously. `raw-handle-seam.test.ts` pins
      // the spread itself rather than leave that to this comment.
      let closed = false;
      const tracked: LocalDatabase = {
        ...db,
        close: () => {
          closed = true;
          db.close();
        },
      };
      handles.push({
        close: () => {
          tracked.close();
        },
        isOpen: () => !closed,
      });
      return tracked;
    },
    openRaw: (): DatabaseSync => {
      const db = new DatabaseSync(dbPath(home));
      handles.push({
        close: () => {
          db.close();
        },
        isOpen: () => db.isOpen,
      });
      return db;
    },
    openHandleCount: (): number => handles.filter((handle) => handle.isOpen()).length,
    onCleanup: (fn: () => void): void => {
      cleanups.push(fn);
    },
    destroy: (): void => {
      if (destroyed) return;
      destroyed = true;
      // Restores run before the handles close: a cleanup may need to widen a
      // mode the test tightened, and it must run whether or not the test threw.
      // A failure here is collected rather than swallowed — discarding it is
      // how an injector's own loud failure (a lock that would not let go, a
      // mode that would not go back) went silent, since `onCleanup` is the
      // wiring those injectors recommend.
      const problems: unknown[] = [];
      for (const fn of cleanups.reverse()) {
        try {
          fn();
        } catch (err) {
          problems.push(err);
        }
      }
      for (const handle of handles) {
        try {
          handle.close();
        } catch {
          // node:sqlite throws on a second close, and a test is free to close a
          // handle itself — an already-closed handle is the expected case here.
        }
      }
      // The tree goes first either way: a cleanup that cannot run must not
      // strand it. Only once it is gone is there anything to report.
      try {
        removeTree(home);
      } catch (err) {
        problems.push(err);
      }
      if (problems.length > 0) {
        throw new AggregateError(problems, 'temp store teardown failed');
      }
    },
  };
}

// Windows refuses to delete a file some handle still has open, where POSIX is
// happy to. This used to swallow that refusal, because a fault test reached it
// legitimately: `openLocalDatabase` did not close its `DatabaseSync` when it
// threw partway through, so on a corrupt or locked store the handle was
// unreachable and nothing could close it before the rm.
//
// That is fixed — the open path closes the handle on every throw — so the
// swallow no longer covers a known-good case, and keeping it would hide the
// next one. An undeletable tree now fails on every platform, which is what makes
// this the regression signal: a store handle that escapes a failed open reddens
// the Windows leg here, and the descriptor counts in `helpers/descriptors.ts`
// redden the POSIX legs.
//
// `rmSync`'s own retries stay. They cover the genuinely transient case — a
// handle on its way out, or a scanner holding a file for a moment — which is a
// different thing from a handle nobody closed.
const STILL_HELD = new Set(['EPERM', 'EBUSY', 'EACCES', 'ENOTEMPTY']);

function removeTree(home: string): void {
  try {
    rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code !== undefined && STILL_HELD.has(code)) {
      // A bare EPERM/EACCES from an rm names neither the tree nor the likely
      // cause, and on the Windows leg that is the whole diagnostic a reader
      // gets. The likely cause is platform-specific: on Windows these codes
      // mean a handle is still open, full stop. On POSIX the same codes are at
      // least as often a directory mode a test set and never restored —
      // removing an entry needs write+execute on its PARENT, not on the entry
      // itself — so a held handle is named second there, not first.
      const likely =
        process.platform === 'win32'
          ? 'a handle still holds a file under it: one the test opened outside the store ' +
            '(use openRaw), or one an open path failed without closing'
          : 'a directory under it is not writable (a mode a test set and did not restore), ' +
            'or a handle still holds a file under it';
      throw new Error(`temp store teardown could not remove ${home} (${code}): ${likely}.`, {
        cause: err,
      });
    }
    throw err;
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
export function withTempStore<T>(
  fn: (store: TempStore) => T,
  prefix?: string,
  options?: TempStoreOptions,
): T {
  const store = createTempStore(prefix, options);
  let result: T;
  try {
    result = fn(store);
  } catch (err) {
    destroyAfterFailure(store, err);
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
      destroyAfterFailure(store, err);
      throw err;
    },
  );
  return settled as T;
}

/**
 * Tear down after the body has already failed, without letting the teardown
 * speak over it.
 *
 * `destroy()` ends in `removeTree`, which rethrows on POSIX by design — a mode
 * a test tightened and never restored surfaces there. Left unguarded, a test
 * that both forgot a restore and failed an assertion reports `EACCES … rmdir`
 * and nothing about the assertion, in the one case where the diagnostic matters
 * most. The teardown failure still travels, as `cause`.
 */
function destroyAfterFailure(store: OwnedTempStore, err: unknown): void {
  try {
    store.destroy();
  } catch (teardownErr) {
    if (err instanceof Error && err.cause === undefined) err.cause = teardownErr;
  }
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
export function useTempStore(prefix?: string, options?: TempStoreOptions): TempStore {
  let current: OwnedTempStore | undefined;

  beforeEach(() => {
    current = createTempStore(prefix, options);
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
    openRaw: () => active().openRaw(),
    openHandleCount: () => active().openHandleCount(),
    onCleanup: (fn: () => void) => {
      active().onCleanup(fn);
    },
  };
}
