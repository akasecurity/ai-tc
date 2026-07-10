import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../database.ts';
import { openLocalDatabase } from '../database.ts';

// The Inventory projects read views must never surface a Claude Code worktree
// CHECKOUT as a project: pre-worktree-fix plugins minted a source_project row
// per `.claude/worktrees/*` session, and an older plugin can re-mint one at any
// time. The checkout is already part of its head project.

let dir: string;
let db: LocalDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-inv-projects-'));
  db = openLocalDatabase(dir);
});

afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('worktree-checkout ghost rows', () => {
  it('are hidden from listProjects and the project stat, browsable or not', async () => {
    db.sourceProject.upsert(
      { url: 'https://github.com/org/payments-api.git', name: 'payments-api', attributes: {} },
      Date.now(),
    );
    db.sourceProject.upsert(
      {
        url: '/home/dev/payments-api/.claude/worktrees/busy-allen-cbd90f',
        name: 'busy-allen-cbd90f',
        attributes: {},
      },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items.map((p) => p.name)).toEqual(['payments-api']);

    // The search path composes the same guard (AND, not a replaced WHERE).
    const searched = await db.inventoryAssets.listProjects('busy-allen');
    expect(searched.items).toEqual([]);

    const stats = await db.inventoryAssets.getInventoryStats();
    expect(stats.byType.project).toBe(1);
  });

  it('hides Windows (backslash-separated) checkout ghosts too', async () => {
    db.sourceProject.upsert(
      {
        url: 'C:\\dev\\payments-api\\.claude\\worktrees\\wt-x',
        name: 'wt-x',
        attributes: {},
      },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items).toEqual([]);
    const stats = await db.inventoryAssets.getInventoryStats();
    expect(stats.byType.project).toBe(0);
  });

  it('keeps a remote-less repo keyed by a plain root path visible', async () => {
    db.sourceProject.upsert(
      { url: '/home/dev/local-only-repo', name: 'local-only-repo', attributes: {} },
      Date.now(),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items.map((p) => p.name)).toEqual(['local-only-repo']);
  });
});
