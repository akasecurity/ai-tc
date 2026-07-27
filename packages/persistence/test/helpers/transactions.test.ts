import { describe, expect, it } from 'vitest';

import { withTempStore } from './temp-store.ts';
import { assertNoOpenTransaction } from './transactions.ts';

// One line, and every "the failure was contained" claim in the fault suite
// rests on it. Gut it and those claims keep reporting success, so it needs a
// gate of its own: it has to fail on an open transaction, it has to leave the
// handle exactly as it found it, and it must not answer for a handle it cannot
// ask.

describe('assertNoOpenTransaction', () => {
  it('throws when the handle is inside a transaction', () => {
    withTempStore((store) => {
      const db = store.openRaw();
      db.exec('BEGIN');
      expect(() => {
        assertNoOpenTransaction(db);
      }).toThrow(/transaction is still open/);
      // The check does not touch the transaction it reports on, so the caller's
      // is still open here and still the caller's to end.
      expect(db.isTransaction).toBe(true);
      db.exec('ROLLBACK');
    });
  });

  it('passes on a handle that is not, and hands it back the way it found it', () => {
    withTempStore((store) => {
      const db = store.openRaw();
      db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
      db.prepare('INSERT INTO t (v) VALUES (?)').run('before');

      expect(() => {
        assertNoOpenTransaction(db);
      }).not.toThrow();

      // Reading `isTransaction` cannot disturb the handle the way a BEGIN and
      // ROLLBACK of its own would: the row survives, the handle stays usable,
      // and asking twice is the same as asking once.
      expect(() => {
        assertNoOpenTransaction(db);
      }).not.toThrow();
      expect(db.isTransaction).toBe(false);
      db.prepare('INSERT INTO t (v) VALUES (?)').run('after');
      expect(db.prepare('SELECT count(*) AS n FROM t').get()).toEqual({ n: 2 });
    });
  });

  it('throws on a handle the caller already closed', () => {
    withTempStore((store) => {
      const db = store.openRaw();
      db.close();
      // Not a transaction fault, but the helper must not report "no transaction
      // open" for a handle it could not ask.
      expect(() => {
        assertNoOpenTransaction(db);
      }).toThrow(/not open/);
    });
  });
});
