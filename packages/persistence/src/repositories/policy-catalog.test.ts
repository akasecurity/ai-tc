import { DatabaseSync } from 'node:sqlite';

import type { InstalledPackInput } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../migrations.ts';
import { SqliteInstalledPacksRepository } from './installed-packs.ts';
import { SqlitePolicyCatalogRepository } from './policy-catalog.ts';

let db: DatabaseSync;
let packs: SqliteInstalledPacksRepository;
let catalog: SqlitePolicyCatalogRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applyMigrations(db);
  packs = new SqliteInstalledPacksRepository(db);
  catalog = new SqlitePolicyCatalogRepository(packs);
});

afterEach(() => {
  db.close();
});

function pack(packId: string, ruleIds: string[]): InstalledPackInput {
  return {
    namespace: 'aka',
    packId,
    version: '1.0.0',
    name: `${packId} detection`,
    rules: ruleIds.map((id) => ({
      specVersion: 1,
      id,
      name: id,
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'x', flags: 'g' },
    })),
  };
}

describe('SqlitePolicyCatalogRepository', () => {
  it('lists the 4 built-ins with live usedBy counts', async () => {
    packs.upsertPacks([pack('secrets', ['a', 'b']), pack('pii', ['c'])]);
    packs.setPolicy('aka', 'secrets', 'block');
    packs.setPolicy('aka', 'pii', 'block');

    const { items } = await catalog.getPolicyList();
    expect(items.map((p) => p.id)).toEqual(['monitor', 'warn', 'redact', 'block']);
    expect(items.every((p) => p.kind === 'builtin' && p.enabled)).toBe(true);
    const block = items.find((p) => p.id === 'block');
    expect(block?.usedByCount).toBe(2);
    expect(items.find((p) => p.id === 'monitor')?.usedByCount).toBe(0);
  });

  it('kind=custom returns an empty list (OSS has no custom policies)', async () => {
    expect((await catalog.getPolicyList('custom')).items).toEqual([]);
  });

  it('stats count the governed detections across every built-in id', async () => {
    packs.upsertPacks([pack('secrets', ['a']), pack('pii', ['b']), pack('code', ['c'])]);
    packs.setPolicy('aka', 'secrets', 'block');
    packs.setPolicy('aka', 'pii', 'redact');

    const stats = await catalog.getPolicyStats();
    expect(stats).toEqual({ policies: 4, builtin: 4, custom: 0, detectionsGoverned: 2 });
  });

  it('detail carries the catalog description + usedBy detections; null for unknown', async () => {
    packs.upsertPacks([pack('secrets', ['a', 'b', 'c'])]);
    packs.setPolicy('aka', 'secrets', 'block');

    const detail = await catalog.getPolicyDetail('block');
    expect(detail?.name).toBe('Block');
    expect(detail?.kind).toBe('builtin');
    expect(detail?.description).toContain('Refuse the request');
    expect(detail?.usedBy).toEqual([
      { id: 'aka/secrets', name: 'secrets detection', ruleCount: 3, enabled: true },
    ]);

    expect(await catalog.getPolicyDetail('bogus')).toBeNull();
  });
});
