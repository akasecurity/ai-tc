// Shared node:sqlite transaction envelopes. One copy of the
// BEGIN/COMMIT/guarded-ROLLBACK sequence so every multi-statement write
// handles a failed commit the same way.

import type { DatabaseSync } from 'node:sqlite';

// Distinguishes the SAVEPOINT of a nested envelope from that of any envelope
// already open on the same handle.
let savepointSeq = 0;

/**
 * Run `fn` inside a single SQLite transaction: BEGIN (or BEGIN IMMEDIATE),
 * then `fn()`, then COMMIT. Any error from `fn()` or COMMIT rolls the
 * transaction back and rethrows the original error.
 *
 * When the handle is already inside a transaction, `fn` runs inside a
 * SAVEPOINT instead: node:sqlite forbids a nested BEGIN, and the outer
 * transaction owns the final COMMIT/ROLLBACK. An error unwinds only this
 * envelope's own work (ROLLBACK TO) and rethrows, leaving the caller's
 * transaction open — the envelope never commits or rolls back a transaction it
 * did not begin. `mode` is ignored while nested; the open transaction already
 * holds its lock.
 */
export function withTransaction(
  db: DatabaseSync,
  fn: () => void,
  mode: 'DEFERRED' | 'IMMEDIATE' = 'DEFERRED',
): void {
  if (db.isTransaction) {
    const savepoint = `aka_sp_${String((savepointSeq += 1))}`;
    db.exec(`SAVEPOINT ${savepoint}`);
    try {
      fn();
      // Merges this savepoint's work into the enclosing transaction; only the
      // outer COMMIT makes it durable.
      db.exec(`RELEASE ${savepoint}`);
    } catch (error) {
      try {
        // ROLLBACK TO rewinds to the savepoint but leaves it on the stack;
        // RELEASE pops it so the caller's transaction is left as it was found.
        db.exec(`ROLLBACK TO ${savepoint}`);
        db.exec(`RELEASE ${savepoint}`);
      } catch {
        // Some SQLite errors unwind the savepoint themselves.
      }
      throw error;
    }
    return;
  }

  db.exec(mode === 'IMMEDIATE' ? 'BEGIN IMMEDIATE' : 'BEGIN');
  try {
    fn();
    db.exec('COMMIT');
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Some SQLite errors abort the transaction themselves.
    }
    throw error;
  }
}

/**
 * `withTransaction` with every error swallowed: returns `true` when the work
 * committed (or, while nested, was released into the caller's transaction),
 * `false` on any failure. A failure persists nothing either way — while nested,
 * the SAVEPOINT rewind keeps a partial write out of the caller's transaction.
 */
export function failOpenTransaction(
  db: DatabaseSync,
  fn: () => void,
  mode: 'DEFERRED' | 'IMMEDIATE' = 'DEFERRED',
): boolean {
  try {
    withTransaction(db, fn, mode);
    return true;
  } catch {
    return false;
  }
}
