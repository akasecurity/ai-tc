/**
 * Store faults a test can inject on purpose: a damaged file, a store it cannot
 * write, a write lock held by someone else, and a store with no room left.
 *
 * The store's own error classification reads one extended result code
 * (SQLITE_CONSTRAINT_UNIQUE), so every other SQLite failure arrives at the
 * fail-open paths as an indistinguishable `Error`. These injectors produce the
 * real codes from the real engine — nothing here mocks node:sqlite or the
 * filesystem — so a test can pin which failure it is actually exercising.
 *
 * Every injector either takes effect or says so: `corruptStore` verifies the
 * damage landed, and `readOnlyStore` reports whether the mode change actually
 * denies writes. On Windows chmod is a no-op for directories, and a process
 * running as root bypasses modes entirely; without that signal a read-only
 * test would pass on a store it could still write.
 */
import {
  accessSync,
  chmodSync,
  closeSync,
  constants,
  existsSync,
  openSync,
  readSync,
  rmSync,
  statSync,
  truncateSync,
  writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';

import { walSidecars } from '../../src/paths.ts';

/** Extended result codes node:sqlite attaches to an error as `errcode`. */
export const SQLITE_BUSY = 5;
export const SQLITE_READONLY = 8;
export const SQLITE_CORRUPT = 11;
export const SQLITE_FULL = 13;
export const SQLITE_NOTADB = 26;
/** SQLITE_READONLY_DIRECTORY — the db is fine, its directory is not writable. */
export const SQLITE_READONLY_DIRECTORY = 1544;

/** The `errcode` node:sqlite carries on an error, or undefined for anything else. */
export function sqliteErrcode(err: unknown): number | undefined {
  return err instanceof Error ? (err as { errcode?: number }).errcode : undefined;
}

// ---------------------------------------------------------------------------
// Corruption
// ---------------------------------------------------------------------------

/**
 * How to damage a store. Each mode fails at a different point, which is the
 * reason to have all three:
 *
 * - `truncate` — the file keeps a valid header but loses its pages, so a read
 *   raises SQLITE_CORRUPT.
 * - `header` — the magic string is gone, so SQLite refuses the file outright
 *   with SQLITE_NOTADB, before any query runs.
 * - `page` — the b-tree page header of the store's second page changes, so the
 *   page no longer declares a valid type. The store opens, and rows outside
 *   the damaged page still read, so only `PRAGMA integrity_check` notices.
 *   This is the quiet one, and the one a fail-open caller is most likely to
 *   carry on through.
 */
export type CorruptionMode = 'truncate' | 'header' | 'page';

/** Bytes kept by `truncate` — enough for the 100-byte header, not the pages. */
const TRUNCATE_TO_BYTES = 1024;
/** SQLite stores the page size at header offset 16, big-endian, 2 bytes. */
const PAGE_SIZE_OFFSET = 16;

function readPageSize(file: string): number {
  const fd = openSync(file, 'r');
  try {
    const header = Buffer.alloc(2);
    readSync(fd, header, 0, 2, PAGE_SIZE_OFFSET);
    const encoded = header.readUInt16BE(0);
    // A page size of 65536 is stored as 1.
    return encoded === 1 ? 65536 : encoded;
  } finally {
    closeSync(fd);
  }
}

function flipByteAt(file: string, offset: number): void {
  const fd = openSync(file, 'r+');
  try {
    const byte = Buffer.alloc(1);
    readSync(fd, byte, 0, 1, offset);
    writeSync(fd, Buffer.from([byte.readUInt8(0) ^ 0xff]), 0, 1, offset);
  } finally {
    closeSync(fd);
  }
}

/** True when the store is damaged in a way SQLite will report. */
function isDamaged(file: string): boolean {
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(file);
    const row = db.prepare('PRAGMA integrity_check').get() as
      { integrity_check?: string } | undefined;
    return row?.integrity_check !== 'ok';
  } catch {
    // Refused at open or at the first read — damaged, and loudly so.
    return true;
  } finally {
    try {
      db?.close();
    } catch {
      // Already torn down by the failure above.
    }
  }
}

/**
 * Damage a real store at a fixed offset — same input, same bytes changed, every
 * run. The store must have no open handle: the WAL sidecars are removed first,
 * because a WAL still holding the live pages would replay over the damage.
 *
 * Throws if the damage did not take, so a corrupted-store test can never pass
 * against a healthy store.
 */
export function corruptStore(file: string, mode: CorruptionMode = 'truncate'): void {
  if (!existsSync(file)) {
    throw new Error(`corruptStore(): no store at ${file}`);
  }
  for (const sidecar of walSidecars(file)) {
    if (existsSync(sidecar)) rmSync(sidecar);
  }

  switch (mode) {
    case 'truncate': {
      const size = statSync(file).size;
      if (size <= TRUNCATE_TO_BYTES) {
        throw new Error(
          `corruptStore('truncate'): ${file} is ${String(size)} bytes, already at or below the ${String(TRUNCATE_TO_BYTES)}-byte target — write to the store first.`,
        );
      }
      truncateSync(file, TRUNCATE_TO_BYTES);
      break;
    }
    case 'header': {
      // Byte 0 of the "SQLite format 3\0" magic string.
      flipByteAt(file, 0);
      break;
    }
    case 'page': {
      const pageSize = readPageSize(file);
      // Byte 0 of page 2 — the b-tree page type. Page 1 is left alone: damaging
      // it would take the file header with it and fail at open instead.
      const offset = pageSize;
      if (statSync(file).size <= offset) {
        throw new Error(
          `corruptStore('page'): ${file} is a single page — write enough rows to reach a second page first.`,
        );
      }
      flipByteAt(file, offset);
      break;
    }
  }

  if (!isDamaged(file)) {
    throw new Error(`corruptStore('${mode}'): ${file} still reads as a healthy store.`);
  }
}

// ---------------------------------------------------------------------------
// Read-only
// ---------------------------------------------------------------------------

export interface ReadOnlyStore {
  /**
   * Whether the mode change actually denies writes. False where the platform
   * ignores POSIX modes, or the process can write regardless — a test that
   * asserts read-only behaviour should skip rather than pass on a writable
   * store.
   */
  readonly effective: boolean;
  /** Put the original modes back. Idempotent. */
  restore(): void;
}

/**
 * Make a store unwritable by mode. The db and any WAL sidecars go to 0444.
 *
 * With `includeDir`, the containing directory goes to 0555 as well, which is
 * the harsher case: in WAL mode SQLite needs to create the -wal/-shm sidecars,
 * so it fails at open with SQLITE_READONLY_DIRECTORY rather than at the first
 * write. Without it, reads keep working and only writes raise SQLITE_READONLY.
 *
 * `includeDir` reaches a raw handle, not `openLocalDatabase`: that path calls
 * `ensureDataDirSync` first, which chmods the data dir back to 0700 — an owner
 * can always widen their own directory again — so only the file mode is left
 * to bite by the time SQLite sees it.
 *
 * `restore()` must run before the tree is deleted — register it with the temp
 * store's `onCleanup`, which `withTempStore` already drains.
 */
export function readOnlyStore(file: string, opts: { includeDir?: boolean } = {}): ReadOnlyStore {
  const targets = [file, ...walSidecars(file)].filter((path) => existsSync(path));
  const dir = dirname(file);
  const original = new Map<string, number>();

  const tighten = (path: string, mode: number): void => {
    original.set(path, statSync(path).mode);
    chmodSync(path, mode);
  };

  for (const path of targets) tighten(path, 0o444);
  if (opts.includeDir) tighten(dir, 0o555);

  // A mode that still permits writing protects nothing; report that rather
  // than let a caller assert against a store it can freely write.
  const denied = (path: string): boolean => {
    try {
      accessSync(path, constants.W_OK);
      return false;
    } catch {
      return true;
    }
  };
  const effective = [...original.keys()].every(denied);

  let restored = false;
  return {
    effective,
    restore(): void {
      if (restored) return;
      restored = true;
      // The directory first: everything else lives inside it.
      if (opts.includeDir) {
        const mode = original.get(dir);
        if (mode !== undefined) chmodSync(dir, mode);
      }
      for (const path of targets) {
        const mode = original.get(path);
        try {
          if (mode !== undefined) chmodSync(path, mode);
        } catch {
          // Already gone, or a platform that never applied the mode.
        }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Write lock held elsewhere
// ---------------------------------------------------------------------------

const STATE = 0;
const RELEASE = 1;

const STATE_HELD = 1;
const STATE_FAILED = 3;

export interface StoreLock {
  /**
   * Give the write lock back and wait until the holder has let go. Idempotent,
   * and a no-op once `holdMs` has already elapsed.
   *
   * It returns only after the holder has closed its handle, so a temp store
   * torn down straight afterwards has no connection left on the file —
   * Windows refuses to delete one that is still open.
   */
  release(): void;
}

export interface LockStoreOptions {
  /**
   * Hold for this long, then release without being asked. Leave it out to hold
   * until `release()`.
   *
   * A hold longer than the store's `busy_timeout` makes another writer fail
   * with SQLITE_BUSY; a shorter one makes it wait and then succeed. Both are
   * worth pinning — one proves the timeout has a limit, the other proves it
   * does its job.
   */
  holdMs?: number;
  /** How long to wait for the lock to be taken before giving up. */
  readyTimeoutMs?: number;
  /** `busy_timeout` for the holder's own handle while it takes the lock. */
  busyTimeoutMs?: number;
}

/**
 * Take the store's write lock (`BEGIN IMMEDIATE`) on another thread and return
 * once it is held.
 *
 * node:sqlite is synchronous, so a lock held on the calling thread could never
 * be contended — the thread would be inside the holder, not the victim. A
 * worker thread holds it instead, and the handshake is a blocking
 * `Atomics.wait` rather than a poll or a sleep, so "the lock is up" is settled
 * before this function returns and the victim can never start early.
 */
export function lockStore(file: string, opts: LockStoreOptions = {}): StoreLock {
  const readyTimeoutMs = opts.readyTimeoutMs ?? 10_000;
  const shared = new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT);
  const signal = new Int32Array(shared);

  const worker = new Worker(new URL('./lock-worker.ts', import.meta.url), {
    workerData: {
      file,
      busyTimeoutMs: opts.busyTimeoutMs ?? 2000,
      holdMs: opts.holdMs ?? null,
      shared,
    },
  });
  // The lock must not be what keeps the test process alive.
  worker.unref();
  worker.on('error', () => {
    // The state slots carry every failure this helper reports. Without a
    // listener Node re-raises a worker error on this thread instead, long
    // after the call that started it returned.
    void worker.terminate();
  });

  Atomics.wait(signal, STATE, 0, readyTimeoutMs);
  const state = Atomics.load(signal, STATE);
  if (state !== STATE_HELD) {
    void worker.terminate();
    throw new Error(
      state === STATE_FAILED
        ? `lockStore(): the holder could not take the write lock on ${file}`
        : `lockStore(): the write lock on ${file} was not taken within ${String(readyTimeoutMs)}ms`,
    );
  }

  let released = false;
  return {
    release(): void {
      if (released) return;
      released = true;
      Atomics.store(signal, RELEASE, 1);
      Atomics.notify(signal, RELEASE);
      // Returns immediately once the holder has moved off STATE_HELD, including
      // when it already released itself after holdMs.
      Atomics.wait(signal, STATE, STATE_HELD, readyTimeoutMs);
      void worker.terminate();
    },
  };
}

// ---------------------------------------------------------------------------
// No room left
// ---------------------------------------------------------------------------

export interface FilledStore {
  /** Lift the cap. Idempotent. */
  restore(): void;
}

/**
 * Cap how far a store may grow on this handle, so the next write that needs a
 * new page raises SQLITE_FULL from the engine itself — no mount, no elevated
 * privileges, and no stand-in for node:sqlite.
 *
 * The cap belongs to the connection, not the file: another handle on the same
 * store is unaffected, so this fills the store for the handle passed in and
 * that handle only. A genuinely full filesystem stays out of reach in CI.
 */
export function fillStore(db: DatabaseSync, opts: { headroomPages?: number } = {}): FilledStore {
  const readPragma = (name: string): number => {
    const row = db.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
    const value = row?.[name];
    if (typeof value !== 'number') {
      throw new Error(`fillStore(): PRAGMA ${name} returned no value`);
    }
    return value;
  };

  const previousMax = readPragma('max_page_count');
  const cap = readPragma('page_count') + (opts.headroomPages ?? 2);
  db.prepare(`PRAGMA max_page_count = ${String(cap)}`).get();

  let restored = false;
  return {
    restore(): void {
      if (restored) return;
      restored = true;
      db.prepare(`PRAGMA max_page_count = ${String(previousMax)}`).get();
    },
  };
}
