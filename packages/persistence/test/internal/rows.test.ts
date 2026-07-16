import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  allRows,
  bindParams,
  boolToInt,
  countBy,
  countScalar,
  getRow,
  intToBool,
  mapRowsTolerant,
} from '../../src/internal/rows.ts';

interface ItemRow {
  id: number;
  name: string;
  kind: string;
  note: string | null;
}

let db: DatabaseSync;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec(
    'CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, note TEXT)',
  );
  const insert = db.prepare('INSERT INTO items (name, kind, note) VALUES (:name, :kind, :note)');
  insert.run({ name: 'alpha', kind: 'a', note: null });
  insert.run({ name: 'beta', kind: 'b', note: 'x' });
  insert.run({ name: 'gamma', kind: 'a', note: null });
});

afterEach(() => {
  db.close();
});

describe('allRows', () => {
  it('returns every row without params', () => {
    const rows = allRows<ItemRow>(db.prepare('SELECT * FROM items ORDER BY id'));
    expect(rows.map((r) => r.name)).toEqual(['alpha', 'beta', 'gamma']);
  });

  it('binds positional-array params by spreading', () => {
    const rows = allRows<ItemRow>(
      db.prepare('SELECT * FROM items WHERE kind = ? AND name <> ? ORDER BY id'),
      ['a', 'gamma'],
    );
    expect(rows.map((r) => r.name)).toEqual(['alpha']);
  });

  it('binds named-object params', () => {
    const rows = allRows<ItemRow>(
      db.prepare('SELECT * FROM items WHERE kind = :kind ORDER BY id'),
      {
        kind: 'a',
      },
    );
    expect(rows.map((r) => r.name)).toEqual(['alpha', 'gamma']);
  });
});

describe('getRow', () => {
  it('returns the first row, typed', () => {
    const row = getRow<ItemRow>(db.prepare('SELECT * FROM items WHERE name = ?'), ['beta']);
    expect(row?.kind).toBe('b');
    expect(row?.note).toBe('x');
  });

  it('returns undefined when nothing matches', () => {
    expect(getRow<ItemRow>(db.prepare('SELECT * FROM items WHERE name = ?'), ['nope'])).toBe(
      undefined,
    );
  });

  it('works without params and with named params', () => {
    expect(getRow<{ n: number }>(db.prepare('SELECT count(*) AS n FROM items'))?.n).toBe(3);
    const row = getRow<ItemRow>(db.prepare('SELECT * FROM items WHERE kind = :kind ORDER BY id'), {
      kind: 'b',
    });
    expect(row?.name).toBe('beta');
  });
});

describe('intToBool / boolToInt', () => {
  it('intToBool accepts 1 and true only', () => {
    expect(intToBool(1)).toBe(true);
    expect(intToBool(true)).toBe(true);
    expect(intToBool(0)).toBe(false);
    expect(intToBool(false)).toBe(false);
    expect(intToBool(null)).toBe(false);
    expect(intToBool(undefined)).toBe(false);
    expect(intToBool('1')).toBe(false);
  });

  it('boolToInt maps to 0/1', () => {
    expect(boolToInt(true)).toBe(1);
    expect(boolToInt(false)).toBe(0);
  });
});

describe('bindParams', () => {
  it('maps undefined properties to null and passes everything else through', () => {
    expect(bindParams({ a: 1, b: undefined, c: null, d: 's' })).toEqual({
      a: 1,
      b: null,
      c: null,
      d: 's',
    });
  });

  it('makes a row with undefined fields bindable in a real INSERT', () => {
    db.prepare('INSERT INTO items (name, kind, note) VALUES (:name, :kind, :note)').run(
      bindParams({ name: 'delta', kind: 'c', note: undefined }),
    );
    const row = getRow<ItemRow>(db.prepare('SELECT * FROM items WHERE name = ?'), ['delta']);
    expect(row?.note).toBe(null);
  });
});

describe('countScalar', () => {
  it('returns the count aliased AS n', () => {
    expect(countScalar(db, 'SELECT count(*) AS n FROM items')).toBe(3);
    expect(countScalar(db, 'SELECT count(*) AS n FROM items WHERE kind = ?', ['a'])).toBe(2);
    expect(
      countScalar(db, 'SELECT count(*) AS n FROM items WHERE kind = :kind', { kind: 'b' }),
    ).toBe(1);
  });

  it('returns 0 when the query yields no row at all', () => {
    expect(countScalar(db, 'SELECT 1 AS n FROM items WHERE 0')).toBe(0);
  });
});

describe('countBy', () => {
  it('returns a key → count Map from k/n aliases', () => {
    const map = countBy(db, 'SELECT kind AS k, count(*) AS n FROM items GROUP BY kind');
    expect(map).toEqual(
      new Map([
        ['a', 2],
        ['b', 1],
      ]),
    );
  });

  it('supports bind params and returns an empty Map for no groups', () => {
    const map = countBy(
      db,
      'SELECT kind AS k, count(*) AS n FROM items WHERE name = ? GROUP BY kind',
      ['nope'],
    );
    expect(map.size).toBe(0);
  });
});

describe('mapRowsTolerant', () => {
  it('skips only the rows whose mapper throws, preserving order', () => {
    const rows = [1, 2, 3, 4];
    const out = mapRowsTolerant(rows, (n) => {
      if (n % 2 === 0) throw new Error(`no evens: ${String(n)}`);
      return n * 10;
    });
    expect(out).toEqual([10, 30]);
  });

  it('returns an empty array when every row fails', () => {
    expect(
      mapRowsTolerant([1, 2], () => {
        throw new Error('always');
      }),
    ).toEqual([]);
  });
});
