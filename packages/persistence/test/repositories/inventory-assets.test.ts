import { DatabaseSync } from 'node:sqlite';

import { ASSET_LIST_META_KEYS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyMigrations } from '../../src/migrations.ts';
import { SqliteInventoryAssetsRepository } from '../../src/repositories/inventory-assets.ts';
import { purgeSampleData } from '../../src/sample-purge.ts';
import { seedSampleFixtures } from '../../src/test-fixtures/index.ts';

let db: DatabaseSync;
let inv: SqliteInventoryAssetsRepository;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  applyMigrations(db);
  seedSampleFixtures(db);
  inv = new SqliteInventoryAssetsRepository(db);
});

afterEach(() => {
  db.close();
});

const PAYMENTS = 'sample:project:payments-api';

describe('SqliteInventoryAssetsRepository over the sample dataset', () => {
  it('stats count assets by type, harnesses, mcp trust, attention', async () => {
    const stats = await inv.getInventoryStats();
    expect(stats.byType).toEqual({ project: 3, skill: 3, mcp: 3, hook: 2, config: 2 });
    expect(stats.harnesses).toBe(2);
    expect(stats.mcpTrust).toEqual({ 'known-good': 1, risky: 1, unapproved: 1 });
    // 6 flagged assets. The sample projects' per-file counts are not findings
    // in the window, so no project adds to it.
    expect(stats.attention).toBe(6);
  });

  it('groups harnesses by resolved id with their assets + projects', async () => {
    const { items } = await inv.listHarnesses();
    expect(items.map((h) => h.id).sort()).toEqual(['claudecode', 'cursor']);
    const cc = items.find((h) => h.id === 'claudecode');
    expect(cc?.assetCount).toBe(10);
    expect(cc?.projects).toHaveLength(3);
    expect(cc?.sessions).toBe(128);
    expect(cc?.categories.map((c) => c.type)).toEqual(['config', 'skill', 'mcp', 'hook']);
    expect(items.find((h) => h.id === 'cursor')?.assetCount).toBe(3);
  });

  it('groups assets config→skill→mcp→hook with the mcp trust rollup', async () => {
    const { groups } = await inv.listAssets({});
    expect(groups.map((g) => g.type)).toEqual(['config', 'skill', 'mcp', 'hook']);
    const mcp = groups.find((g) => g.type === 'mcp');
    expect(mcp?.total).toBe(3);
    expect(mcp?.trustRollup).toEqual({ 'known-good': 1, risky: 1, unapproved: 1 });
  });

  it('asset detail annotates unapproved MCP tools with a blocked risk', async () => {
    const detail = await inv.getAsset('sample:asset:shell-runner-mcp');
    expect(detail?.type).toBe('mcp');
    expect(detail?.trust).toBe('unapproved');
    expect(detail?.tools?.[0]?.risk).toContain('Arbitrary command execution');
    expect(await inv.getAsset('nope')).toBeNull();
  });

  it('project tree browse mode splits folders and root files', async () => {
    const tree = await inv.getProjectTree(PAYMENTS, {});
    expect(tree?.folders?.map((f) => f.name)).toEqual(['docs', 'src', 'vendor']);
    expect(tree?.files.map((f) => f.name).sort()).toEqual(['.env.example', 'package.json']);
    // Folder rollup counts descendants.
    const src = tree?.folders?.find((f) => f.name === 'src');
    expect(src?.accessCounts.total).toBe(7);
  });

  it('project tree blocked mode returns auto-blocked files only', async () => {
    const tree = await inv.getProjectTree(PAYMENTS, { filter: 'blocked' });
    expect(tree?.files.map((f) => f.path).sort()).toEqual([
      '.env.example',
      'src/config/secrets.ts',
    ]);
  });

  it('project file detail carries project context; null for unknown', async () => {
    const file = await inv.getProjectFile(PAYMENTS, 'src/config/secrets.ts');
    expect(file?.access).toBe('blocked');
    expect(file?.isCustom).toBe(false);
    expect(file?.project.language).toBe('TypeScript');
    expect(await inv.getProjectFile(PAYMENTS, 'no/such/file')).toBeNull();
  });

  it('setFileAccess writes an override and clears on default', async () => {
    expect(inv.setFileAccess(PAYMENTS, 'src/index.ts', 'blocked')).toBe(true);
    let file = await inv.getProjectFile(PAYMENTS, 'src/index.ts');
    expect(file?.access).toBe('blocked');
    expect(file?.isCustom).toBe(true);

    // 'approved' is the project default → clears the override.
    inv.setFileAccess(PAYMENTS, 'src/index.ts', 'approved');
    file = await inv.getProjectFile(PAYMENTS, 'src/index.ts');
    expect(file?.access).toBe('approved');
    expect(file?.isCustom).toBe(false);

    expect(inv.setFileAccess(PAYMENTS, 'no/such/file', 'blocked')).toBe(false);
  });

  it('setMcpTrust writes/clears on mcp assets and rejects non-mcp', async () => {
    expect(inv.setMcpTrust('sample:asset:github-mcp', 'risky')).toBe('ok');
    expect((await inv.getAsset('sample:asset:github-mcp'))?.trust).toBe('risky');

    inv.setMcpTrust('sample:asset:github-mcp', 'known-good'); // back to base → clears
    expect((await inv.getAsset('sample:asset:github-mcp'))?.trust).toBe('known-good');

    expect(inv.setMcpTrust('sample:asset:commit-helper', 'risky')).toBe('not_mcp');
    expect(inv.setMcpTrust('nope', 'risky')).toBe('not_found');
  });
});

describe('legacy sample purge over the inventory fixtures', () => {
  it('purgeSampleData fully clears the sample inventory', async () => {
    expect((await inv.getInventoryStats()).byType.skill).toBe(3);

    purgeSampleData(db);
    const stats = await inv.getInventoryStats();
    expect(stats.byType).toEqual({ project: 0, skill: 0, mcp: 0, hook: 0, config: 0 });
    expect(stats.harnesses).toBe(0);
    expect((await inv.listHarnesses()).items).toEqual([]);
  });
});

describe('endpoint counts', () => {
  it('carries none: the local store is one machine, so the views hide them', async () => {
    const { items: harnesses } = await inv.listHarnesses();
    const { groups } = await inv.listAssets({});
    const { items: projects } = await inv.listProjects();
    const assets = [
      ...groups.flatMap((g) => g.items),
      ...harnesses.flatMap((h) => h.categories.flatMap((c) => c.assets)),
    ];
    const detail = await inv.getAsset('sample:asset:shell-runner-mcp');

    expect(assets.length).toBeGreaterThan(0);
    expect(projects.length).toBeGreaterThan(0);
    for (const row of [...assets, ...projects, ...harnesses.flatMap((h) => h.projects)]) {
      expect(row).not.toHaveProperty('machines');
    }
    for (const row of assets) expect(row).not.toHaveProperty('variants');
    for (const harness of harnesses) expect(harness).not.toHaveProperty('machines');
    expect(detail).not.toHaveProperty('machines');
    expect(detail).not.toHaveProperty('seenOn');
  });
});

describe('list meta', () => {
  it('carries only the keys the tables read, while the detail carries the whole record', async () => {
    const { groups } = await inv.listAssets({});
    const { items: harnesses } = await inv.listHarnesses();
    const listed = [
      ...groups.flatMap((g) => g.items),
      ...harnesses.flatMap((h) => h.categories.flatMap((c) => c.assets)),
    ];

    expect(listed.length).toBeGreaterThan(0);
    for (const asset of listed) {
      if (asset.type === 'project') throw new Error('a project in an asset list');
      const allowed: readonly string[] = ASSET_LIST_META_KEYS[asset.type];
      for (const key of Object.keys(asset.meta)) expect(allowed).toContain(key);
    }
    const trimmed = [];
    for (const asset of listed) {
      const detail = await inv.getAsset(asset.id);
      if (detail && Object.keys(detail.meta).length > Object.keys(asset.meta).length) {
        trimmed.push(asset.id);
      }
    }
    expect(trimmed.length).toBeGreaterThan(0);
  });
});
