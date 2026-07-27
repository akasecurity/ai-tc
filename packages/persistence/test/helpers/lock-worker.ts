/**
 * Holds `BEGIN IMMEDIATE` on a store from a thread of its own, so the thread
 * that started it can go on to attempt a write and meet a real write lock.
 *
 * The two sides talk through one Int32Array in shared memory rather than
 * messages: the starting thread blocks in `Atomics.wait` until this worker
 * reports the lock is held, which makes "the lock is up before the victim
 * writes" an ordering guarantee instead of a race. Slot 0 carries this
 * worker's state, slot 1 carries the release request.
 *
 * Failure is reported through slot 0 and never thrown. A throw here escapes as
 * an uncaught exception on the thread that started the worker, arriving after
 * whichever test caused it has already finished — the starting thread reads
 * the slot and raises its own error instead.
 *
 * This file is loaded by Node directly, outside the test runner's transform,
 * so it stays on node: builtins and plain type annotations.
 */
import { DatabaseSync } from 'node:sqlite';
import { workerData } from 'node:worker_threads';

const STATE = 0;
const RELEASE = 1;

const STATE_HELD = 1;
const STATE_RELEASED = 2;
const STATE_FAILED = 3;

interface LockWorkerData {
  file: string;
  busyTimeoutMs: number;
  holdMs: number | null;
  shared: SharedArrayBuffer;
}

const { file, busyTimeoutMs, holdMs, shared } = workerData as LockWorkerData;
const signal = new Int32Array(shared);

function announce(state: number): void {
  Atomics.store(signal, STATE, state);
  Atomics.notify(signal, STATE);
}

// The starting thread is parked in Atomics.wait and cannot receive this
// worker's 'error' event, so anything that escapes below has to reach it
// through the state slot or not at all — otherwise the caller waits out its
// whole ready timeout and reports a lock that was never taken.
process.on('uncaughtException', () => {
  announce(STATE_FAILED);
});

function takeLock(): DatabaseSync | undefined {
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(file);
    db.exec(`PRAGMA busy_timeout = ${String(busyTimeoutMs)}`);
    // No journal_mode here. The write lock does not need WAL — BEGIN IMMEDIATE
    // takes one in any journal mode — and the mode change is the one statement
    // busy_timeout cannot govern: SQLite refuses it outright against another
    // writer rather than retrying, so it can only add a failure this helper
    // would then misreport as a lock it could not take. Setting it would also
    // convert the store under test, which a fault injector has no business
    // doing.
    // BEGIN IMMEDIATE takes the write lock up front rather than on first write,
    // so the lock is held the instant this returns — no statement needed.
    db.exec('BEGIN IMMEDIATE');
    return db;
  } catch {
    try {
      db?.close();
    } catch {
      // The handle never opened, or already tore itself down.
    }
    return undefined;
  }
}

const held = takeLock();
if (!held) {
  announce(STATE_FAILED);
} else {
  announce(STATE_HELD);

  // Park until the starting thread asks for the lock back, or until the hold
  // elapses. Blocking here rather than on a timer keeps the lock on this
  // thread's stack for exactly as long as it is meant to be held.
  Atomics.wait(signal, RELEASE, 0, holdMs ?? Infinity);

  // ROLLBACK, not COMMIT: the lock existed to block another writer, and the
  // transaction is not meant to leave anything behind.
  held.exec('ROLLBACK');
  held.close();
  announce(STATE_RELEASED);
}
