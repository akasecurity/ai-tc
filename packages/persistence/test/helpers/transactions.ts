/**
 * Proof that a handle is not sitting inside a transaction.
 *
 * A fault that leaves one open is worse than the fault: the connection holds
 * its locks, every later write on it joins a transaction nobody meant to
 * start, and the store looks healthy from outside. SQLite makes the check
 * free — `BEGIN` throws inside an open transaction — so a fault test can pin
 * "the failure was contained" rather than only "the failure happened".
 */
import type { DatabaseSync } from 'node:sqlite';

/** Throws if `db` is inside a transaction. */
export function assertNoOpenTransaction(db: DatabaseSync): void {
  db.exec('BEGIN');
  db.exec('ROLLBACK');
}
