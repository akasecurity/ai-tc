import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { recordProjectInventory } from './project-inventory.ts';

const REMOTE_URL = 'https://github.com/acme/ai-tc.git';

// Lay down a minimal on-disk git repo: a `.git` DIRECTORY (what findGitRoot
// detects) whose `config` carries the origin remote the identity resolves from.
function initRepo(root: string, remoteUrl?: string): void {
  mkdirSync(join(root, '.git'));
  const config = remoteUrl ? `[remote "origin"]\n\turl = ${remoteUrl}\n` : '';
  writeFileSync(join(root, '.git', 'config'), config);
}

// Turn `root` into a parent repo with a LINKED WORKTREE the way git lays it out
// (`.git` file → `<parent>/.git/worktrees/<name>` → `commondir`). Returns the
// worktree root.
function linkedWorktree(root: string, name: string): string {
  const gitdir = join(root, '.git', 'worktrees', name);
  mkdirSync(gitdir, { recursive: true });
  writeFileSync(join(gitdir, 'commondir'), '../..\n');
  const wtRoot = join(root, '.claude', 'worktrees', name);
  mkdirSync(wtRoot, { recursive: true });
  writeFileSync(join(wtRoot, '.git'), `gitdir: ${gitdir}\n`);
  return wtRoot;
}

// Raw at-rest rows, straight from the store file — assertions on what actually
// hit disk, independent of any read port.
function storedProjects(dir: string): { url: string; name: string | null }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw.prepare('SELECT url, name FROM source_project').all() as unknown as {
      url: string;
      name: string | null;
    }[];
  } finally {
    raw.close();
  }
}

function storedFiles(dir: string): { path: string; origin: string }[] {
  const raw = new DatabaseSync(join(dir, DB_FILENAME), { readOnly: true });
  try {
    return raw.prepare('SELECT path, origin FROM project_file ORDER BY path').all() as unknown as {
      path: string;
      origin: string;
    }[];
  } finally {
    raw.close();
  }
}

let root: string;
let store: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-project-inventory-'));
  store = mkdtempSync(join(tmpdir(), 'aka-project-inventory-db-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(store, { recursive: true, force: true });
});

describe('recordProjectInventory', () => {
  it('records the project row and its file tree for a repo with a remote', () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'app.ts'), 'export const a = 1;\n');
    writeFileSync(join(root, 'README.md'), '# readme\n');
    writeFileSync(join(root, '.gitignore'), 'scratch.env\n');
    writeFileSync(join(root, 'scratch.env'), 'local-only\n');

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, root);
    } finally {
      db.close();
    }

    expect(result).not.toBeNull();
    expect(result?.name).toBe('ai-tc');
    expect(result?.url).toBe(REMOTE_URL);
    expect(result?.fileCount).toBe(3); // app.ts + README.md + .gitignore
    expect(result?.truncated).toBe(false);

    expect(storedProjects(store)).toEqual([{ url: REMOTE_URL, name: 'ai-tc' }]);
    // Gitignored files are local scratch, not part of the project as shared.
    expect(storedFiles(store)).toEqual([
      { path: '.gitignore', origin: 'config' },
      { path: 'README.md', origin: 'docs' },
      { path: 'app.ts', origin: 'source' },
    ]);
  });

  it('resolves the whole worktree from a target deep inside the repo', () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'top.ts'), 'export {};\n');
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, 'src', 'inner.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, join(root, 'src'));
    } finally {
      db.close();
    }

    expect(result?.url).toBe(REMOTE_URL);
    expect(storedFiles(store).map((f) => f.path)).toEqual(['src/inner.ts', 'top.ts']);
  });

  it('falls back to the worktree root path for a repo with no remote', () => {
    initRepo(root);
    writeFileSync(join(root, 'app.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, root);
    } finally {
      db.close();
    }

    // Posix-normalized path identity (a no-op outside win32).
    expect(result?.url).toBe(root.split('\\').join('/'));
    expect(storedProjects(store)).toHaveLength(1);
  });

  it('returns null and writes nothing for a target outside any git repo', () => {
    writeFileSync(join(root, 'loose.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, root);
    } finally {
      db.close();
    }

    expect(result).toBeNull();
    expect(storedProjects(store)).toEqual([]);
    expect(storedFiles(store)).toEqual([]);
  });

  it('still upserts the project row when the walk yields no files', () => {
    initRepo(root, REMOTE_URL);

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, root);
    } finally {
      db.close();
    }

    expect(result?.fileCount).toBe(0);
    expect(storedProjects(store)).toEqual([{ url: REMOTE_URL, name: 'ai-tc' }]);
    expect(storedFiles(store)).toEqual([]);
  });

  it('re-running prunes files that no longer exist and stays one project row', () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'keep.ts'), 'export {};\n');
    writeFileSync(join(root, 'gone.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    try {
      recordProjectInventory(db, root);
      rmSync(join(root, 'gone.ts'));
      const second = recordProjectInventory(db, root);
      expect(second?.fileCount).toBe(1);
    } finally {
      db.close();
    }

    expect(storedProjects(store)).toHaveLength(1);
    expect(storedFiles(store).map((f) => f.path)).toEqual(['keep.ts']);
  });

  it('never throws for a missing target', () => {
    const db = openLocalDatabase(store);
    try {
      expect(recordProjectInventory(db, join(root, 'does-not-exist'))).toBeNull();
    } finally {
      db.close();
    }
  });

  it('records the whole worktree for a FILE target', () => {
    initRepo(root, REMOTE_URL);
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, 'src', 'inner.ts'), 'export {};\n');
    writeFileSync(join(root, 'top.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    let result;
    try {
      result = recordProjectInventory(db, join(root, 'src', 'inner.ts'));
    } finally {
      db.close();
    }

    expect(result?.url).toBe(REMOTE_URL);
    expect(storedFiles(store).map((f) => f.path)).toEqual(['src/inner.ts', 'top.ts']);
  });

  it('writes nothing for a missing target INSIDE a repo', () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'app.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    try {
      expect(recordProjectInventory(db, join(root, 'tpyo'))).toBeNull();
    } finally {
      db.close();
    }

    expect(storedProjects(store)).toEqual([]);
    expect(storedFiles(store)).toEqual([]);
  });

  it('records a linked worktree under the CANONICAL parent project, truncated, without pruning', () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'main-only.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    try {
      recordProjectInventory(db, root);

      const wt = linkedWorktree(root, 'wt-branch');
      writeFileSync(join(wt, 'branch-only.ts'), 'export {};\n');
      const second = recordProjectInventory(db, wt);

      // The branch checkout is a partial view of the project by construction.
      expect(second?.url).toBe(REMOTE_URL);
      expect(second?.truncated).toBe(true);
    } finally {
      db.close();
    }

    // No per-checkout project row, and the head-only file was never pruned.
    expect(storedProjects(store)).toEqual([{ url: REMOTE_URL, name: 'ai-tc' }]);
    expect(storedFiles(store).map((f) => f.path)).toEqual(['branch-only.ts', 'main-only.ts']);
  });

  it("leaves the user/local inventory row's host link untouched", () => {
    initRepo(root, REMOTE_URL);
    writeFileSync(join(root, 'app.ts'), 'export {};\n');

    const db = openLocalDatabase(store);
    try {
      // A SessionStart-shaped pass links user/local to the host row.
      db.ensureInventory({
        host: {
          objectType: 'host',
          identityKey: 'test-host',
          title: 'test-host',
          attributes: { host_name: 'test-host', os: 'darwin', os_version: '1', arch: 'arm64' },
        },
        harness: { objectType: 'harness', identityKey: 'claude-code', attributes: {} },
      });
      recordProjectInventory(db, root);
    } finally {
      db.close();
    }

    const raw = new DatabaseSync(join(store, DB_FILENAME), { readOnly: true });
    try {
      const user = raw
        .prepare("SELECT host_id FROM inventory WHERE object_type = 'user'")
        .get() as { host_id: string | null };
      expect(user.host_id).not.toBeNull();
    } finally {
      raw.close();
    }
  });
});
