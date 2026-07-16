import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import {
  isUniqueConstraintError,
  SQLITE_CONSTRAINT_UNIQUE,
} from '../../src/internal/sqlite-errors.ts';

describe('isUniqueConstraintError', () => {
  it('matches a real UNIQUE violation from node:sqlite', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE u (v TEXT NOT NULL UNIQUE)');
      const insert = db.prepare('INSERT INTO u (v) VALUES (?)');
      insert.run('x');
      let caught: unknown;
      try {
        insert.run('x');
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(Error);
      expect(isUniqueConstraintError(caught)).toBe(true);
    } finally {
      db.close();
    }
  });

  it('matches on the extended result code alone', () => {
    const err = Object.assign(new Error('constraint'), { errcode: SQLITE_CONSTRAINT_UNIQUE });
    expect(isUniqueConstraintError(err)).toBe(true);
  });

  it('matches on the message alone', () => {
    expect(isUniqueConstraintError(new Error('UNIQUE constraint failed: u.v'))).toBe(true);
  });

  it('rejects other errors and non-errors', () => {
    expect(isUniqueConstraintError(new Error('NOT NULL constraint failed: u.v'))).toBe(false);
    expect(isUniqueConstraintError(Object.assign(new Error('constraint'), { errcode: 1299 }))).toBe(
      false,
    );
    expect(isUniqueConstraintError('UNIQUE constraint failed')).toBe(false);
    expect(isUniqueConstraintError(undefined)).toBe(false);
  });

  it('rejects a real non-UNIQUE constraint violation', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE nn (v TEXT NOT NULL)');
      let caught: unknown;
      try {
        db.prepare('INSERT INTO nn (v) VALUES (?)').run(null);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(Error);
      expect(isUniqueConstraintError(caught)).toBe(false);
    } finally {
      db.close();
    }
  });
});
