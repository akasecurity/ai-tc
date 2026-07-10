import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ProjectFileInput, ProjectFilesScan } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../database.ts';
import { openLocalDatabase } from '../database.ts';

// The real project-file scan write path (recordProjectFiles) read back through
// the SAME views the Inventory page uses (listProjects access counts +
// getProjectTree folders/files) — the write is only correct if the page renders.

let dir: string;
let db: LocalDatabase;
let projectId: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-projfiles-db-'));
  db = openLocalDatabase(dir);
  projectId = db.sourceProject.upsert(
    { url: 'https://github.com/org/payments-api.git', name: 'payments-api', attributes: {} },
    Date.now(),
  );
});

afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function file(path: string, overrides?: Partial<ProjectFileInput>): ProjectFileInput {
  return {
    path,
    name: path.slice(path.lastIndexOf('/') + 1),
    origin: 'source',
    defaultAccess: 'approved',
    ...overrides,
  };
}

function scan(files: ProjectFileInput[], truncated = false): ProjectFilesScan {
  return { files, truncated, scannedAt: new Date().toISOString() };
}

describe('recordProjectFiles', () => {
  it('writes the tree the Inventory page reads: folders, files, access counts', async () => {
    db.recordProjectFiles(
      projectId,
      scan([file('README.md', { origin: 'docs' }), file('src/app.ts'), file('src/lib/util.ts')]),
    );

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items[0]?.accessCounts).toEqual({
      open: 0,
      approved: 3,
      blocked: 0,
      total: 3,
    });

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    expect(tree?.folders?.map((f) => f.name)).toEqual(['src']);
    expect(tree?.folders?.[0]?.accessCounts.total).toBe(2);
    expect(tree?.files.map((f) => f.name)).toEqual(['README.md']);
  });

  it('replace-set: a rescan updates, adds, and prunes vanished files', async () => {
    db.recordProjectFiles(projectId, scan([file('a.ts'), file('gone.ts')]));
    db.recordProjectFiles(projectId, scan([file('a.ts', { origin: 'config' }), file('new.ts')]));

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    expect(tree?.files.map((f) => [f.name, f.origin])).toEqual([
      ['a.ts', 'config'],
      ['new.ts', 'source'],
    ]);
  });

  it('a truncated scan never prunes beyond what it re-saw', async () => {
    db.recordProjectFiles(projectId, scan([file('a.ts'), file('b.ts')]));
    db.recordProjectFiles(projectId, scan([file('a.ts')], true));

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    expect(tree?.files.map((f) => f.name)).toEqual(['a.ts', 'b.ts']);
  });

  it('an empty scan is dropped, never wiping the stored tree', async () => {
    db.recordProjectFiles(projectId, scan([file('a.ts')]));
    db.recordProjectFiles(projectId, scan([]));

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    expect(tree?.files.map((f) => f.name)).toEqual(['a.ts']);
  });

  it('scopes the prune to the scanned project', async () => {
    const otherId = db.sourceProject.upsert(
      { url: 'https://github.com/org/other.git', name: 'other', attributes: {} },
      Date.now(),
    );
    db.recordProjectFiles(otherId, scan([file('other.ts')]));
    db.recordProjectFiles(projectId, scan([file('mine.ts')]));

    const other = await db.inventoryAssets.getProjectTree(otherId, {});
    expect(other?.files.map((f) => f.name)).toEqual(['other.ts']);
  });

  it('a rescan preserves a user file-access override (keyed by path)', async () => {
    db.recordProjectFiles(projectId, scan([file('secret.ts')]));
    expect(db.inventoryAssets.setFileAccess(projectId, 'secret.ts', 'blocked')).toBe(true);
    db.recordProjectFiles(projectId, scan([file('secret.ts')]));

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    expect(tree?.files[0]?.access).toBe('blocked');
  });
});

describe('reconcileWorktreeProjects', () => {
  const HEAD = '/home/dev/payments-api';

  function ghostRow(path: string): string {
    return db.sourceProject.upsert(
      { url: path, name: path.slice(path.lastIndexOf('/') + 1), attributes: {} },
      Date.now(),
    );
  }

  it('folds checkout-path ghost rows into the canonical row, remapping audit refs', async () => {
    const ghostA = ghostRow(`${HEAD}/.claude/worktrees/busy-allen-cbd90f`);
    const ghostB = ghostRow('/somewhere/else/wt-b');
    // A session audit root referencing the ghost. The store runs with
    // PRAGMA foreign_keys = ON, so the ghost delete below succeeding at all
    // proves this reference was remapped to the canonical row first.
    db.auditEvents.insertAuditEvent({
      id: 'sess-ghost',
      eventType: 'session',
      startedAt: new Date().toISOString(),
      sourceProjectId: ghostA,
    });

    db.reconcileWorktreeProjects(projectId, HEAD, '/somewhere/else/wt-b');

    const ids = (await db.inventoryAssets.listProjects()).items.map((p) => p.id);
    expect(ids).toEqual([projectId]);
    expect(ids).not.toContain(ghostA);
    expect(ids).not.toContain(ghostB);
  });

  it('never touches the canonical row or unrelated path projects', async () => {
    const unrelated = ghostRow('/home/dev/other-repo');
    db.reconcileWorktreeProjects(projectId, HEAD, `${HEAD}/.claude/worktrees/wt-x`);

    const projects = await db.inventoryAssets.listProjects();
    expect(projects.items.map((p) => p.id).sort()).toEqual([projectId, unrelated].sort());
  });

  it('escapes LIKE metacharacters in the head root', () => {
    const trickyHead = '/home/dev/pay_ments';
    // Would match the underscore-wildcard pattern if unescaped, but lives under
    // a DIFFERENT head ('payXments' ≠ 'pay_ments') — the sweep must not delete
    // it. (Asserted on the row itself: the read views hide ALL checkout paths.)
    const lookalike = ghostRow('/home/dev/payXments/.claude/worktrees/wt-x');
    db.reconcileWorktreeProjects(projectId, trickyHead, `${trickyHead}/.claude/worktrees/wt-y`);

    expect(db.sourceProject.findById(lookalike)).toBeDefined();
  });

  it('migrates ghost file-access overrides to the canonical row (its own wins on conflict)', async () => {
    db.recordProjectFiles(projectId, scan([file('secret.ts'), file('config.ts')]));
    // Overrides a user set while the ghost row WAS the project's identity.
    const ghost = ghostRow(`${HEAD}/.claude/worktrees/wt-old`);
    db.recordProjectFiles(ghost, scan([file('secret.ts'), file('config.ts')]));
    expect(db.inventoryAssets.setFileAccess(ghost, 'secret.ts', 'blocked')).toBe(true);
    expect(db.inventoryAssets.setFileAccess(ghost, 'config.ts', 'open')).toBe(true);
    // The canonical row already carries its own override for config.ts.
    expect(db.inventoryAssets.setFileAccess(projectId, 'config.ts', 'blocked')).toBe(true);

    db.reconcileWorktreeProjects(projectId, HEAD, `${HEAD}/.claude/worktrees/wt-new`);

    const tree = await db.inventoryAssets.getProjectTree(projectId, {});
    const access = new Map(tree?.files.map((f) => [f.path, f.access]));
    expect(access.get('secret.ts')).toBe('blocked'); // migrated from the ghost
    expect(access.get('config.ts')).toBe('blocked'); // canonical's own override kept
    expect(db.sourceProject.findById(ghost)).toBeUndefined();
  });

  it("never folds the repo's own remote-less-era row on a plain-clone session (worktreeRoot === headRoot)", async () => {
    // The repo lived at HEAD with no remote: its row is keyed by the path — a
    // LEGITIMATE identity, not a ghost. The user blocked a file on it. When a
    // remote is added later, the next plain-clone session reconciles with
    // worktreeRoot === headRoot — and must not touch the old row or its override.
    const pathKeyed = ghostRow(HEAD);
    db.recordProjectFiles(pathKeyed, scan([file('secret.ts')]));
    expect(db.inventoryAssets.setFileAccess(pathKeyed, 'secret.ts', 'blocked')).toBe(true);

    db.reconcileWorktreeProjects(projectId, HEAD, HEAD);

    expect(db.sourceProject.findById(pathKeyed)).toBeDefined();
    const tree = await db.inventoryAssets.getProjectTree(pathKeyed, {});
    expect(tree?.files[0]?.access).toBe('blocked');
  });

  it('folds Windows (backslash-separated) ghost rows the posix patterns miss', () => {
    const winHead = 'C:\\dev\\payments-api';
    const ghost = ghostRow(`${winHead}\\.claude\\worktrees\\wt-old`);
    db.reconcileWorktreeProjects(projectId, winHead, `${winHead}\\.claude\\worktrees\\wt-new`);

    expect(db.sourceProject.findById(ghost)).toBeUndefined();
  });
});
