import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// git gives a submodule checked out inside a linked worktree an `origin` on
// local disk — the parent repository's gitdir — and leaves the real forge URL
// on a second remote. A resolver that took `origin` unconditionally recorded
// that checkout under the gitdir path, once per worktree, named after the
// submodule folder. Those rows are ghosts: a `.git` directory is git's own
// storage and is never a project in its own right.

const store = useTempStore('aka-inv-gitdir-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

const REAL = 'https://github.com/org/app.git';

describe('gitdir ghost rows', () => {
  it('are hidden from listProjects and the project stat', async () => {
    db.sourceProject.upsert({ url: REAL, name: 'app', attributes: {} }, Date.now());
    db.sourceProject.upsert(
      {
        url: '/home/dev/parent/.git/worktrees/confident-wu-b7173e/modules/oss',
        name: 'oss',
        attributes: {},
      },
      Date.now(),
    );

    const { items } = await db.inventoryAssets.listProjects();
    const stats = await db.inventoryAssets.getInventoryStats();

    expect(items.map((p) => p.name)).toEqual(['app']);
    expect(stats.byType.project).toBe(1);
  });

  it('are hidden in the Windows separator flavor too', async () => {
    db.sourceProject.upsert({ url: REAL, name: 'app', attributes: {} }, Date.now());
    db.sourceProject.upsert(
      {
        url: 'C:\\dev\\parent\\.git\\worktrees\\wt\\modules\\oss',
        name: 'oss',
        attributes: {},
      },
      Date.now(),
    );

    const { items } = await db.inventoryAssets.listProjects();

    expect(items.map((p) => p.name)).toEqual(['app']);
  });

  // P5. The SHARED submodule gitdir is a legitimate identity: a submodule whose
  // only remote is that path keys on it and new events attach to it, so hiding
  // it would leave a project being written to that no read surface can reach.
  it('leave the SHARED submodule gitdir visible, since it can be a live identity', async () => {
    db.sourceProject.upsert({ url: REAL, name: 'app', attributes: {} }, Date.now());
    db.sourceProject.upsert(
      { url: '/home/dev/parent/.git/modules/oss', name: 'oss', attributes: {} },
      Date.now(),
    );

    const { items } = await db.inventoryAssets.listProjects();
    const stats = await db.inventoryAssets.getInventoryStats();

    expect(items.map((p) => p.name).sort()).toEqual(['app', 'oss']);
    expect(stats.byType.project).toBe(2);
  });

  // The control. Without it a filter that hid EVERY path-keyed row, or every
  // row whose url merely contains `git`, would pass every case above.
  it('leaves a real checkout-path project visible', async () => {
    db.sourceProject.upsert(
      { url: '/home/dev/local-only-repo', name: 'local-only-repo', attributes: {} },
      Date.now(),
    );
    db.sourceProject.upsert({ url: REAL, name: 'app', attributes: {} }, Date.now());

    const { items } = await db.inventoryAssets.listProjects();

    expect(items.map((p) => p.name).sort()).toEqual(['app', 'local-only-repo']);
  });
});

describe('reconcileWorktreeProjects folds a superseded identity', () => {
  it('folds the local-disk remote row into the repository it is a clone of', () => {
    const ghostUrl = '/home/dev/parent/.git/modules/oss';
    const canonicalId = db.sourceProject.upsert(
      { url: REAL, name: 'app', attributes: {} },
      Date.now(),
    );
    const ghostId = db.sourceProject.upsert(
      { url: ghostUrl, name: 'oss', attributes: {} },
      Date.now(),
    );
    expect(ghostId).not.toBe(canonicalId);

    db.reconcileWorktreeProjects(canonicalId, '/home/dev/parent/oss', '/home/dev/parent/oss', [
      ghostUrl,
    ]);

    expect(db.sourceProject.findById(ghostId)).toBeUndefined();
    expect(db.sourceProject.findById(canonicalId)).toBeDefined();
  });

  // The control: the fold is keyed on the url EXACTLY, so it can never reach a
  // row belonging to another repository.
  it('leaves a row whose url it was not given', () => {
    const canonicalId = db.sourceProject.upsert(
      { url: REAL, name: 'app', attributes: {} },
      Date.now(),
    );
    const otherId = db.sourceProject.upsert(
      { url: '/home/dev/other/.git/modules/oss', name: 'oss', attributes: {} },
      Date.now(),
    );

    db.reconcileWorktreeProjects(canonicalId, '/home/dev/parent/oss', '/home/dev/parent/oss', [
      '/home/dev/parent/.git/modules/oss',
    ]);

    expect(db.sourceProject.findById(otherId)).toBeDefined();
  });

  it('still folds nothing extra when given no superseded urls', () => {
    const canonicalId = db.sourceProject.upsert(
      { url: REAL, name: 'app', attributes: {} },
      Date.now(),
    );
    const ghostId = db.sourceProject.upsert(
      { url: '/home/dev/parent/.git/modules/oss', name: 'oss', attributes: {} },
      Date.now(),
    );

    db.reconcileWorktreeProjects(canonicalId, '/home/dev/parent/oss', '/home/dev/parent/oss');

    expect(db.sourceProject.findById(ghostId)).toBeDefined();
  });
});
