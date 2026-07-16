import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { failOpenTransaction, withTransaction } from '../../src/internal/transactions.ts';

let db: DatabaseSync;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)');
});

afterEach(() => {
  db.close();
});

function rowCount(): number {
  return (db.prepare('SELECT count(*) AS n FROM t').get() as { n: number }).n;
}

// Proves no transaction is left open: BEGIN throws inside an open transaction.
function assertNoOpenTransaction(): void {
  db.exec('BEGIN');
  db.exec('ROLLBACK');
}

describe('withTransaction', () => {
  it('commits: rows written inside fn persist', () => {
    withTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
      db.prepare('INSERT INTO t (v) VALUES (?)').run('b');
    });
    expect(rowCount()).toBe(2);
    assertNoOpenTransaction();
  });

  it('rolls back and rethrows the original error when fn throws', () => {
    const boom = new Error('boom');
    let caught: unknown;
    try {
      withTransaction(db, () => {
        db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
        throw boom;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(boom);
    expect(rowCount()).toBe(0);
    assertNoOpenTransaction();
  });

  it('rethrows the original error even when ROLLBACK itself fails', () => {
    const boom = new Error('after manual rollback');
    let caught: unknown;
    try {
      withTransaction(db, () => {
        // Aborting the transaction inside fn makes the envelope's ROLLBACK
        // throw ("no transaction is active"), which must be swallowed.
        db.exec('ROLLBACK');
        throw boom;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(boom);
    assertNoOpenTransaction();
  });

  it('runs IMMEDIATE mode end-to-end', () => {
    withTransaction(
      db,
      () => {
        db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
      },
      'IMMEDIATE',
    );
    expect(rowCount()).toBe(1);
    assertNoOpenTransaction();
  });

  it('joins a caller-owned transaction rather than committing on its own', () => {
    db.exec('BEGIN');
    db.prepare('INSERT INTO t (v) VALUES (?)').run('outer');
    withTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('inner');
    });
    // Still the caller's transaction, with both rows visible inside it.
    expect(db.isTransaction).toBe(true);
    expect(rowCount()).toBe(2);
    // The caller's boundary decides: its ROLLBACK discards the nested work too,
    // which it could not do had the envelope committed independently.
    db.exec('ROLLBACK');
    expect(rowCount()).toBe(0);
    assertNoOpenTransaction();
  });

  it('unwinds only its own work when fn throws while nested, leaving the caller to continue', () => {
    db.exec('BEGIN');
    db.prepare('INSERT INTO t (v) VALUES (?)').run('outer');
    const boom = new Error('boom');
    let caught: unknown;
    try {
      withTransaction(db, () => {
        db.prepare('INSERT INTO t (v) VALUES (?)').run('inner');
        throw boom;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(boom);
    // Only the envelope's own row is gone; the caller's transaction is still
    // open and still owns its row — never rolled back from under it.
    expect(db.isTransaction).toBe(true);
    expect(rowCount()).toBe(1);
    db.exec('COMMIT');
    expect(rowCount()).toBe(1);
    assertNoOpenTransaction();
  });

  it('nests re-entrantly: each envelope unwinds to its own savepoint', () => {
    db.exec('BEGIN');
    withTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
      try {
        withTransaction(db, () => {
          db.prepare('INSERT INTO t (v) VALUES (?)').run('b');
          throw new Error('inner');
        });
      } catch {
        // The inner envelope's row is rewound; this one's work continues.
      }
      db.prepare('INSERT INTO t (v) VALUES (?)').run('c');
    });
    expect(rowCount()).toBe(2);
    expect((db.prepare('SELECT group_concat(v) AS v FROM t').get() as { v: string }).v).toBe('a,c');
    db.exec('ROLLBACK');
    expect(rowCount()).toBe(0);
    assertNoOpenTransaction();
  });
});

describe('failOpenTransaction', () => {
  it('returns true when the transaction commits', () => {
    const ok = failOpenTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
    });
    expect(ok).toBe(true);
    expect(rowCount()).toBe(1);
  });

  it('returns false and swallows the error when fn throws; nothing persists', () => {
    const ok = failOpenTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
      throw new Error('boom');
    });
    expect(ok).toBe(false);
    expect(rowCount()).toBe(0);
    assertNoOpenTransaction();
  });

  it('supports IMMEDIATE mode', () => {
    const ok = failOpenTransaction(
      db,
      () => {
        db.prepare('INSERT INTO t (v) VALUES (?)').run('a');
      },
      'IMMEDIATE',
    );
    expect(ok).toBe(true);
    expect(rowCount()).toBe(1);
  });

  it('returns true while nested and its work joins the caller’s transaction', () => {
    db.exec('BEGIN');
    db.prepare('INSERT INTO t (v) VALUES (?)').run('outer');
    const ok = failOpenTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('inner');
    });
    expect(ok).toBe(true);
    expect(db.isTransaction).toBe(true);
    expect(rowCount()).toBe(2);
    db.exec('ROLLBACK');
    expect(rowCount()).toBe(0);
    assertNoOpenTransaction();
  });

  it('returns false while nested and keeps its partial write out of the caller’s transaction', () => {
    db.exec('BEGIN');
    db.prepare('INSERT INTO t (v) VALUES (?)').run('outer');
    const ok = failOpenTransaction(db, () => {
      db.prepare('INSERT INTO t (v) VALUES (?)').run('inner');
      throw new Error('boom');
    });
    expect(ok).toBe(false);
    // Swallowing the error must not leave the half-done write behind: the
    // caller's transaction is still open and holds only its own row, so its
    // COMMIT cannot make the abandoned write durable.
    expect(db.isTransaction).toBe(true);
    expect(rowCount()).toBe(1);
    db.exec('COMMIT');
    expect(rowCount()).toBe(1);
    assertNoOpenTransaction();
  });
});
