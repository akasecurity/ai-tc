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

/**
 * A temp store the caller destroys by hand. Prefer `withTempStore` (scoped) or
 * `useTempStore` (hook-driven); reach for this only when neither shape fits.
 */
export function createTempStore(prefix = 'aka-temp-store-'): OwnedTempStore {
  const home = mkdtempSync(join(tmpdir(), prefix));
  // Both subdirs up front, through the same helper the product uses: a bare
  // `mkdirSync` mode is umask-masked and is not applied to a directory that
  // already exists, so `ensureDataDirSync`'s follow-up chmod is what makes 0700
  // a guarantee rather than a request. `data/` would otherwise appear only on
  // the first `open()`, and a test seeding the store by hand — a
  // policy-cache.json, a read-only directory — would meet an absent path.
  ensureDataDirSync(settingsDir(home));
  ensureDataDirSync(dataDir(home));

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
    openRaw: () => active().openRaw(),
    openHandleCount: () => active().openHandleCount(),
    onCleanup: (fn: () => void) => {
      active().onCleanup(fn);
    },
  };
}
