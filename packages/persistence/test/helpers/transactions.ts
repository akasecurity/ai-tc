/**
 * Proof that a handle is not sitting inside a transaction.
 *
 * A fault that leaves one open is worse than the fault: the connection holds
 * its locks, every later write on it joins a transaction nobody meant to
 * start, and the store looks healthy from outside. So a fault test pins "the
 * failure was contained" rather than only "the failure happened".
 *
 * The check reads `db.isTransaction`, the same property the package's own
 * transaction envelopes branch on. Asking with a BEGIN/ROLLBACK pair would
 * mutate the handle it is inspecting — and if that ROLLBACK threw, on a locked
 * or corrupt store, it would leave open the very transaction it exists to
 * disprove. A closed handle throws here rather than reporting "no transaction
 * open" for a handle it could not ask.
 */
import type { DatabaseSync } from 'node:sqlite';

/** Throws if `db` is inside a transaction, or is not open. */
export function assertNoOpenTransaction(db: DatabaseSync): void {
  if (db.isTransaction) {
    throw new Error('assertNoOpenTransaction(): a transaction is still open on this handle');
  }
}
