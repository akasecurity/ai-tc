import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../migrations.ts';
import { SqlitePoliciesRepository } from './policies.ts';

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
