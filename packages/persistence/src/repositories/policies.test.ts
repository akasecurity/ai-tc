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
