import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import {
  containsPattern,
  escapeLikePattern,
  likeAny,
  placeholders,
} from '../../src/internal/sql-text.ts';

describe('escapeLikePattern', () => {
  it('escapes backslash FIRST, then % and _', () => {
    expect(escapeLikePattern('\\')).toBe('\\\\');
    expect(escapeLikePattern('%')).toBe('\\%');
    expect(escapeLikePattern('_')).toBe('\\_');
    // A pre-escaped input: the backslash doubles before %/_ get their own
    // backslash — never the other way around.
    expect(escapeLikePattern('\\%')).toBe('\\\\\\%');
    expect(escapeLikePattern('a_b%c\\d')).toBe('a\\_b\\%c\\\\d');
  });

  it('leaves plain text untouched', () => {
    expect(escapeLikePattern('plain text')).toBe('plain text');
  });
});

describe('placeholders', () => {
  it('produces a comma-separated run of n placeholders', () => {
    expect(placeholders(0)).toBe('');
    expect(placeholders(1)).toBe('?');
    expect(placeholders(3)).toBe('?, ?, ?');
  });
});

describe('containsPattern', () => {
  it('wraps the escaped query in %…%', () => {
    expect(containsPattern('abc')).toBe('%abc%');
    expect(containsPattern('100%')).toBe('%100\\%%');
  });
});

describe('likeAny', () => {
  it('emits clauses byte-identical to the hand-written repository SQL', () => {
    // Pins that likeAny's output stays byte-identical to the hand-written LIKE
    // clauses the call sites (shares.ts, inventory-assets.ts) used before
    // adopting it.
    expect(likeAny(['d.name', 'd.category'])).toBe(
      "(d.name LIKE ? ESCAPE '\\' OR d.category LIKE ? ESCAPE '\\')",
    );
    expect(likeAny(['a.name', 'a.sub'])).toBe(
      "(a.name LIKE ? ESCAPE '\\' OR a.sub LIKE ? ESCAPE '\\')",
    );
    expect(likeAny(['name', 'url'])).toBe("(name LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\')");
  });

  it('handles a single expression', () => {
    expect(likeAny(['e.url'])).toBe("(e.url LIKE ? ESCAPE '\\')");
  });

  it('one bind placeholder per expression', () => {
    const clause = likeAny(['a', 'b', 'c']);
    expect(clause.match(/\?/g)).toHaveLength(3);
  });

  it('runs against a real table and matches LIKE metacharacters literally', () => {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE d (name TEXT NOT NULL, category TEXT NOT NULL)');
      const insert = db.prepare('INSERT INTO d (name, category) VALUES (?, ?)');
      insert.run('100% real', 'metrics');
      insert.run('100x real', 'metrics');
      insert.run('other', 'contains 100% too');
      const stmt = db.prepare(
        `SELECT count(*) AS n FROM d WHERE ${likeAny(['d.name', 'd.category'])}`,
      );
      const pattern = containsPattern('100%');
      const { n } = stmt.get(pattern, pattern) as { n: number };
      expect(n).toBe(2);
    } finally {
      db.close();
    }
  });
});
