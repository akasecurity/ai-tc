import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import { SqlitePoliciesRepository } from '../../src/repositories/policies.ts';

let db: DatabaseSync;
let repo: SqlitePoliciesRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  applyMigrations(db);
  repo = new SqlitePoliciesRepository(db);
});

afterEach(() => {
  db.close();
});

describe('upsertCategoryAction', () => {
  it('inserts a new per-category policy then updates it in place (no duplicate)', async () => {
    repo.upsertCategoryAction('secret', 'warn');
    let pols = await repo.readPolicies();
    const secret = pols.filter((p) => (p.target as { category?: string }).category === 'secret');
    expect(secret).toHaveLength(1);
    expect(secret[0]?.action).toBe('warn');

    repo.upsertCategoryAction('secret', 'block');
    pols = await repo.readPolicies();
    const secret2 = pols.filter((p) => (p.target as { category?: string }).category === 'secret');
    expect(secret2).toHaveLength(1); // still ONE row, not two
    expect(secret2[0]?.action).toBe('block');
  });

  it('getCategoryAction returns the stored action or undefined', () => {
    expect(repo.getCategoryAction('secret')).toBeUndefined();
    repo.upsertCategoryAction('secret', 'block');
    expect(repo.getCategoryAction('secret')).toBe('block');
    expect(repo.getCategoryAction('pii')).toBeUndefined();
  });

  it('re-enables a previously-disabled category row on upsert', () => {
    repo.upsertCategoryAction('secret', 'block');
    db.prepare(
      `UPDATE policies SET enabled = 0 WHERE scope = 'global' AND json_extract(target, '$.category') = 'secret'`,
    ).run();
    repo.upsertCategoryAction('secret', 'warn');
    const row = db
      .prepare(
        `SELECT enabled FROM policies WHERE scope = 'global' AND json_extract(target, '$.category') = 'secret'`,
      )
      .get() as { enabled: number };
    expect(row.enabled).toBe(1);
  });
});

describe('seedDefaults', () => {
  const categoryRows = () =>
    db
      .prepare(
        `SELECT json_extract(target, '$.category') AS category, action, created_at AS c, updated_at AS u
           FROM policies WHERE scope = 'global' ORDER BY category`,
      )
      .all() as { category: string; action: string; c: number; u: number }[];

  it('seeds every category at Monitor on an empty store', () => {
    repo.seedDefaults();
    const rows = categoryRows();
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => r.action === 'log')).toBe(true);
  });

  it('moves a row still exactly as an earlier build seeded it to Monitor, once', () => {
    db.prepare(
      `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
       VALUES ('a', 'global', '{"category":"secret"}', 'warn', 1, 1000, 1000),
              ('b', 'global', '{"category":"pii"}', 'warn', 1, 1000, 2000),
              ('c', 'global', '{"category":"financial"}', 'block', 1, 1000, 1000)`,
    ).run();
    repo.seedDefaults();
    const byCategory = Object.fromEntries(categoryRows().map((r) => [r.category, r]));
    // Untouched seed: moved.
    expect(byCategory.secret?.action).toBe('log');
    // Written after seeding (updated_at moved): a choice somebody made, kept.
    expect(byCategory.pii?.action).toBe('warn');
    // Not the seeded value for its category: kept.
    expect(byCategory.financial?.action).toBe('block');

    // A second open changes nothing.
    const before = JSON.stringify(categoryRows());
    repo.seedDefaults();
    expect(JSON.stringify(categoryRows())).toBe(before);
  });
});

describe('seedDefaults on a store an earlier build wrote', () => {
  // Before this build an INSERT through upsertCategoryAction left updated_at
  // equal to created_at, so these rows look like seeds by timestamp alone.
  const insert = (id: string, category: string, action: string, at: number) =>
    db
      .prepare(
        `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
         VALUES (:id, 'global', :target, :action, 1, :at, :at)`,
      )
      .run({ id, target: JSON.stringify({ category }), action, at });

  it('keeps a choice whose action no seed ever wrote, so fill-gaps reads it as chosen', () => {
    insert('s', 'secret', 'warn', 1_000);
    insert('c', 'custom', 'block', 1_000);
    repo.seedDefaults();
    expect(repo.getCategoryAction('custom')).toBe('block');
    expect(repo.isCategoryChosen('custom')).toBe(true);
    // The untouched seed is still a seed.
    expect(repo.isCategoryChosen('secret')).toBe(false);
  });

  it('keeps a row created after the seed batch, even at the seed value or Monitor', () => {
    insert('s', 'secret', 'warn', 1_000);
    // A category a later release added, chosen long after the store was seeded.
    insert('p', 'pii', 'warn', 1_000 + 86_400_000);
    insert('f', 'financial', 'log', 1_000 + 86_400_000);
    repo.seedDefaults();
    expect(repo.getCategoryAction('pii')).toBe('warn');
    expect(repo.isCategoryChosen('pii')).toBe(true);
    expect(repo.isCategoryChosen('financial')).toBe(true);
    // The seed batch itself is still moved to Monitor.
    expect(repo.getCategoryAction('secret')).toBe('log');
    expect(repo.isCategoryChosen('secret')).toBe(false);
  });

  it('is a no-op on a second open', () => {
    insert('s', 'secret', 'warn', 1_000);
    insert('c', 'custom', 'block', 1_000);
    repo.seedDefaults();
    const read = () => JSON.stringify(db.prepare('SELECT * FROM policies ORDER BY id').all());
    const before = read();
    repo.seedDefaults();
    expect(read()).toBe(before);
  });
});

describe('isCategoryChosen', () => {
  it('is false for a row still as seeded and true once anything writes it', () => {
    repo.seedDefaults();
    expect(repo.isCategoryChosen('secret')).toBe(false);
    repo.upsertCategoryAction('secret', 'log');
    // Same action, but somebody chose it.
    expect(repo.isCategoryChosen('secret')).toBe(true);
  });

  it('is true for a row a posture inserts where none was seeded, and false for no row', () => {
    expect(repo.isCategoryChosen('pii')).toBe(false);
    repo.upsertCategoryAction('pii', 'warn');
    expect(repo.isCategoryChosen('pii')).toBe(true);
  });
});

describe('capCategoryActions', () => {
  it('caps block/redact rows to warn, leaves warn/log rows untouched, returns the changed count', () => {
    repo.upsertCategoryAction('secret', 'block');
    repo.upsertCategoryAction('financial', 'redact');
    repo.upsertCategoryAction('code_flaw', 'warn');
    repo.upsertCategoryAction('config', 'log');

    const changed = repo.capCategoryActions();

    expect(changed).toBe(2);
    expect(repo.getCategoryAction('secret')).toBe('warn');
    expect(repo.getCategoryAction('financial')).toBe('warn');
    expect(repo.getCategoryAction('code_flaw')).toBe('warn');
    expect(repo.getCategoryAction('config')).toBe('log');
  });

  it('is a no-op when no category is set to block/redact', () => {
    repo.upsertCategoryAction('secret', 'warn');
    expect(repo.capCategoryActions()).toBe(0);
    expect(repo.getCategoryAction('secret')).toBe('warn');
  });

  it('leaves a global rule-targeted block/redact policy untouched', () => {
    repo.upsertCategoryAction('secret', 'block');
    db.prepare(
      `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
       VALUES (:id, 'global', :target, 'block', 1, :now, :now)`,
    ).run({
      id: 'rule-targeted-row',
      target: JSON.stringify({ ruleId: 'secrets/aws-access-key' }),
      now: Date.now(),
    });

    const changed = repo.capCategoryActions();

    expect(changed).toBe(1); // only the category row
    expect(repo.getCategoryAction('secret')).toBe('warn');
    const ruleRow = db
      .prepare('SELECT action FROM policies WHERE id = :id')
      .get({ id: 'rule-targeted-row' }) as { action: string };
    expect(ruleRow.action).toBe('block');
  });
});
