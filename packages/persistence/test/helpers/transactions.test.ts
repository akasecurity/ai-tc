import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import type { TempStore } from './temp-store.ts';
import { withTempStore } from './temp-store.ts';
import { assertNoOpenTransaction } from './transactions.ts';

// Two lines that read like a no-op, and every "the failure was contained" claim
// in the fault suite rests on them. Gut the helper and those claims keep
// reporting success, so the helper needs a gate of its own: it has to fail on an
// open transaction, and it has to leave a clean handle exactly as it found it.

/**
 * A raw handle on a store that exists. `data/` is created by
 * `openLocalDatabase`, so a raw handle taken before any `open()` has no
 * directory to create its file in.
 */
function rawHandle(store: TempStore): DatabaseSync {
  store.open().close();
  return new DatabaseSync(store.dbFile);
}

describe('assertNoOpenTransaction', () => {
  it('throws when the handle is inside a transaction', () => {
    withTempStore((store) => {
      const db = rawHandle(store);
      db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
      db.exec('BEGIN');
      try {
        // The helper's own BEGIN is what fails, so its ROLLBACK never runs and
        // the caller's transaction is still open afterwards — this test owns
        // closing it, not the helper.
        expect(() => {
          assertNoOpenTransaction(db);
        }).toThrow();
      } finally {
        db.exec('ROLLBACK');
        db.close();
      }
    });
  });

  it('passes on a handle that is not, and hands it back the way it found it', () => {
    withTempStore((store) => {
      const db = rawHandle(store);
      db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)');
      db.prepare('INSERT INTO t (v) VALUES (?)').run('before');

      expect(() => {
        assertNoOpenTransaction(db);
      }).not.toThrow();

      // It works by opening and rolling back a transaction of its own, so the
      // handle must come back usable, outside a transaction, with nothing the
      // rollback swept up on the way.
      expect(() => {
        assertNoOpenTransaction(db);
      }).not.toThrow();
      db.prepare('INSERT INTO t (v) VALUES (?)').run('after');
      expect(db.prepare('SELECT count(*) AS n FROM t').get()).toEqual({ n: 2 });

      db.close();
    });
  });

  it('throws on a handle the caller already closed', () => {
    withTempStore((store) => {
      const db = rawHandle(store);
      db.close();
      // Not a transaction fault, but the helper must not report "no transaction
      // open" for a handle it could not ask.
      expect(() => {
        assertNoOpenTransaction(db);
      }).toThrow();
    });
  });
});
