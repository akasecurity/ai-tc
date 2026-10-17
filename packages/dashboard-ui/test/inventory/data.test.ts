import type { AssetSummary, ProjectSummary } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_SELECTION,
  type InventoryNavData,
  metaText,
  resolveInventorySelection,
  statusKeys,
} from '../../src/inventory/data.ts';

function project(overrides: Partial<ProjectSummary> = {}): ProjectSummary {
  return {
    id: 'proj-1',
    name: 'web-app',
    repo: 'acme/web-app',
    visibility: 'private',
    language: 'TypeScript',
    policyDefault: 'approved',
    updatedAt: '2026-09-01T00:00:00.000Z',
    accessCounts: { open: 1, approved: 0, blocked: 0, total: 1 },
    findingsCount: 0,
    ...overrides,
  };
}

function asset(overrides: Partial<AssetSummary> = {}): AssetSummary {
  return {
    id: 'a-1',
    type: 'skill',
    name: 'review',
    sub: 'Skill',
    flags: [],
    meta: {},
    ...overrides,
  };
}

describe('statusKeys', () => {
  it('reads a project with findings as needing attention, and one without as OK', () => {
    expect(statusKeys(project({ findingsCount: 3 }))).toEqual(['findings']);
    expect(statusKeys(project())).toEqual([]);
  });

  it("adds an MCP server's risky or unapproved trust to its flags, most severe first", () => {
    expect(statusKeys(asset({ type: 'mcp', trust: 'risky', flags: ['stale', 'risk'] }))).toEqual([
      'risk',
      'risky',
      'stale',
    ]);
    expect(statusKeys(asset({ type: 'mcp', trust: 'unapproved' }))).toEqual(['unapproved']);
    expect(statusKeys(asset({ type: 'mcp', trust: 'known-good' }))).toEqual([]);
  });
});

describe('metaText', () => {
  it('returns scalars as text, joins string lists and drops everything else', () => {
    const meta = { a: 'x', b: 3, c: true, d: ['K1', 'K2'], e: [], f: { nested: 1 }, g: '' };
    expect(metaText(meta, 'a')).toBe('x');
    expect(metaText(meta, 'b')).toBe('3');
    expect(metaText(meta, 'c')).toBe('true');
    expect(metaText(meta, 'd')).toBe('K1, K2');
    expect(metaText(meta, 'e')).toBeNull();
    expect(metaText(meta, 'f')).toBeNull();
    expect(metaText(meta, 'g')).toBeNull();
    expect(metaText(meta, 'missing')).toBeNull();
  });
});

describe('resolveInventorySelection', () => {
  const data: InventoryNavData = {
    harnesses: [
      {
        id: 'claudecode',
        projects: [{ id: 'proj-1' }],
        categories: [{ type: 'skill', assets: [{ id: 'a-1' }] }],
      },
      { id: 'cursor', projects: [], categories: [] },
    ],
    projects: [],
    assetGroups: [{ type: 'mcp', items: [{ id: 'm-1' }] }],
  };

  it('defaults the harness to the first one and keeps a harness that still exists', () => {
    expect(resolveInventorySelection(DEFAULT_SELECTION, data).harness).toBe('claudecode');
    expect(
      resolveInventorySelection({ ...DEFAULT_SELECTION, harness: 'cursor' }, data).harness,
    ).toBe('cursor');
    expect(
      resolveInventorySelection({ ...DEFAULT_SELECTION, harness: 'codex' }, data).harness,
    ).toBe('claudecode');
  });

  it('keeps an opened row that exists anywhere and closes one that is gone', () => {
    const open = (type: 'project' | 'skill' | 'mcp', id: string) =>
      resolveInventorySelection({ ...DEFAULT_SELECTION, item: { type, id } }, data).item;
    expect(open('project', 'proj-1')).toEqual({ type: 'project', id: 'proj-1' });
    expect(open('skill', 'a-1')).toEqual({ type: 'skill', id: 'a-1' });
    expect(open('mcp', 'm-1')).toEqual({ type: 'mcp', id: 'm-1' });
    expect(open('project', 'gone')).toBeNull();
  });

  it('closes an opened asset whose type does not match the asset with that id', () => {
    const open = (type: 'skill' | 'mcp', id: string) =>
      resolveInventorySelection({ ...DEFAULT_SELECTION, item: { type, id } }, data).item;
    expect(open('mcp', 'a-1')).toBeNull();
    expect(open('skill', 'm-1')).toBeNull();
  });

  it('has no harness to select when none are loaded', () => {
    const empty = { harnesses: [], projects: [], assetGroups: [] };
    expect(resolveInventorySelection(DEFAULT_SELECTION, empty).harness).toBeNull();
  });
});
