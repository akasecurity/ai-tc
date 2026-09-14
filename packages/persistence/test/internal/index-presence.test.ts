import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import {
  createIndexProbe,
  INDEX_PRESENCE_SQL,
  SCHEMA_VERSION_SQL,
} from '../../src/internal/index-presence.ts';
import { type RecordedQuery, recordingConnection } from '../helpers/query-plans.ts';
import { withTempStore } from '../helpers/temp-store.ts';

type HostMethod = (...args: unknown[]) => unknown;

function withMemoryDb<T>(fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE t (a TEXT)');
    return fn(db);
  } finally {
    db.close();
  }
}

/**
 * A stand-in for `db` that counts `get` executions per SQL text. Methods are
 * re-bound to their own objects because node:sqlite's host objects reject a
 * proxy as the receiver.
 */
function countingGets(db: DatabaseSync, counts: Map<string, number>): DatabaseSync {
  return new Proxy(db, {
    get(target, prop) {
      if (prop !== 'prepare') {
        const value: unknown = Reflect.get(target, prop, target);
        return typeof value === 'function' ? (value as HostMethod).bind(target) : value;
      }
      return (sql: string) => {
        const stmt = target.prepare(sql);
        return new Proxy(stmt, {
          get(stmtTarget, stmtProp) {
            const value: unknown = Reflect.get(stmtTarget, stmtProp, stmtTarget);
            if (typeof value !== 'function') return value;
            const method = (value as HostMethod).bind(stmtTarget);
            if (stmtProp !== 'get') return method;
            return (...args: unknown[]): unknown => {
              counts.set(sql, (counts.get(sql) ?? 0) + 1);
              return method(...args);
            };
          },
        });
      };
    },
  });
}

describe('createIndexProbe', () => {
  it('reports an index built after the probe was created', () => {
    withMemoryDb((db) => {
      const has = createIndexProbe(db);
      expect(has('idx_t_a')).toBe(false);
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      expect(has('idx_t_a')).toBe(true);
    });
  });

  it('stops reporting an index once it is dropped', () => {
    // A statement pinned with INDEXED BY fails to prepare once its index is
    // gone, so a probe that remembered "present" would hand a caller that error.
    withMemoryDb((db) => {
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      const has = createIndexProbe(db);
      expect(has('idx_t_a')).toBe(true);
      db.exec('DROP INDEX idx_t_a');
      expect(has('idx_t_a')).toBe(false);
    });
  });

  it('matches only an index of exactly that name', () => {
    withMemoryDb((db) => {
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      const has = createIndexProbe(db);
      expect(has('t')).toBe(false);
      expect(has('idx_t')).toBe(false);
      expect(has('idx_t_a')).toBe(true);
    });
  });

  it('follows a CREATE and a DROP that another connection commits', () => {
    withTempStore((store) => {
      const reader = store.openRaw();
      const writer = store.openRaw();
      reader.exec('PRAGMA journal_mode = WAL');
      writer.exec('CREATE TABLE t (a TEXT)');
      const has = createIndexProbe(reader);
      expect(has('idx_t_a')).toBe(false);
      writer.exec('CREATE INDEX idx_t_a ON t (a)');
      expect(has('idx_t_a')).toBe(true);
      writer.exec('DROP INDEX idx_t_a');
      expect(has('idx_t_a')).toBe(false);
    });
  });

  it('answers from the snapshot of a transaction its connection holds open', () => {
    withTempStore((store) => {
      const reader = store.openRaw();
      const writer = store.openRaw();
      reader.exec('PRAGMA journal_mode = WAL');
      writer.exec('CREATE TABLE t (a TEXT)');
      const has = createIndexProbe(reader);
      reader.exec('BEGIN');
      try {
        expect(has('idx_t_a')).toBe(false);
        writer.exec('CREATE INDEX idx_t_a ON t (a)');
        expect(has('idx_t_a')).toBe(false);
      } finally {
        reader.exec('COMMIT');
      }
      expect(has('idx_t_a')).toBe(true);
    });
  });

  it('matches a name regardless of ASCII case, as INDEXED BY does', () => {
    withMemoryDb((db) => {
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      const has = createIndexProbe(db);
      expect(has('IDX_T_A')).toBe(true);
      expect(db.prepare('SELECT a FROM t INDEXED BY IDX_T_A').all()).toEqual([]);
    });
  });

  it('caches nothing it learned inside a transaction that rolled back', () => {
    withTempStore((store) => {
      const reader = store.openRaw();
      const writer = store.openRaw();
      reader.exec('PRAGMA journal_mode = WAL');
      writer.exec('CREATE TABLE t (a TEXT)');
      const has = createIndexProbe(reader);
      expect(has('idx_t_a')).toBe(false);
      reader.exec('BEGIN');
      reader.exec('CREATE INDEX idx_t_a ON t (a)');
      // Inside the transaction the uncommitted index is visible.
      expect(has('idx_t_a')).toBe(true);
      reader.exec('ROLLBACK');
      // The rollback put the schema version back, so this commit lands on the
      // number the uncommitted CREATE had taken.
      writer.exec('CREATE INDEX idx_t_other ON t (a)');
      expect(has('idx_t_a')).toBe(false);
      expect(() => reader.prepare('SELECT a FROM t INDEXED BY idx_t_a')).toThrow(/no such index/);
    });
  });

  it('caches nothing it learned inside a savepoint that rolled back', () => {
    withMemoryDb((db) => {
      const has = createIndexProbe(db);
      db.exec('BEGIN');
      db.exec('SAVEPOINT s');
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      expect(has('idx_t_a')).toBe(true);
      db.exec('ROLLBACK TO s');
      db.exec('RELEASE s');
      db.exec('CREATE INDEX idx_t_other ON t (a)');
      db.exec('COMMIT');
      expect(has('idx_t_a')).toBe(false);
    });
  });

  it('looks a name up once while the schema holds, and again after it changes', () => {
    withMemoryDb((db) => {
      const counts = new Map<string, number>();
      const has = createIndexProbe(countingGets(db, counts));
      expect([has('idx_t_a'), has('idx_t_a'), has('idx_t_a')]).toEqual([false, false, false]);
      expect(counts.get(INDEX_PRESENCE_SQL)).toBe(1);
      expect(counts.get(SCHEMA_VERSION_SQL)).toBe(3);
      db.exec('CREATE INDEX idx_t_a ON t (a)');
      expect(has('idx_t_a')).toBe(true);
      expect(counts.get(INDEX_PRESENCE_SQL)).toBe(2);
    });
  });
});

describe('recordingConnection and the probe', () => {
  it("records a read's own statement and none of the probe's", () => {
    withMemoryDb((db) => {
      const recorded: RecordedQuery[] = [];
      const spy = recordingConnection(db, recorded);
      const has = createIndexProbe(spy);
      expect(has('idx_t_a')).toBe(false);
      spy.prepare('SELECT a FROM t').all();
      // The read's statement is the positive control: an empty list would also
      // satisfy "no probe statement was recorded".
      expect(recorded.map((q) => q.sql)).toEqual(['SELECT a FROM t']);
    });
  });
});
