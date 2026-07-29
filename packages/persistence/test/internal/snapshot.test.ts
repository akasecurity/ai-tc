import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  backupPath,
  discardStore,
  moveStoreAside,
  snapshotStore,
} from '../../src/internal/snapshot.ts';
import { corruptStore } from '../helpers/fault-injection.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-snapshot-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/**
 * A real store with `rows` rows, left open. The rows go in as ONE transaction:
 * a per-row commit is a per-row fsync, which is slow enough on Windows CI to
 * reach the per-test timeout on its own.
 */
function openStore(file: string, rows = 1): DatabaseSync {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('CREATE TABLE corpus (id INTEGER PRIMARY KEY, v TEXT)');
  const insert = db.prepare('INSERT INTO corpus (v) VALUES (?)');
  db.exec('BEGIN');
  for (let i = 0; i < rows; i += 1) {
    insert.run(`prompt-${String(i)}`);
  }
  db.exec('COMMIT');
  return db;
}

describe('backupPath', () => {
  it('is unique across calls inside one millisecond', () => {
    // Millisecond time alone is not unique: the hooks, the CLI and the dashboard
    // share one store, so two of them can enter the same recovery path in the
    // same millisecond. VACUUM INTO refuses a target that already exists, and
    // the loser's cleanup would then delete the winner's finished backup.
    const names = new Set(Array.from({ length: 500 }, () => backupPath('/data/aka.db', 'legacy')));
    expect(names.size).toBe(500);
  });

  it('carries the tag and keeps the .bak suffix', () => {
    expect(backupPath('/data/aka.db', 'pre-drop')).toMatch(
      /^\/data\/aka\.db\.pre-drop\.\d+\.[0-9a-f]{8}\.bak$/,
    );
  });

  it('is not guessable from the store path and the clock', () => {
    // A guessable name in a loosely-permissioned data dir is a symlink target:
    // SQLite follows a link at its output path.
    const name = backupPath('/data/aka.db', 'legacy');
    const millis = /\.legacy\.(\d+)\./.exec(name)?.[1];
    expect(millis).toBeDefined();
    expect(name).not.toBe(`/data/aka.db.legacy.${String(millis)}.bak`);
  });
});

describe('snapshotStore', () => {
  it('publishes a complete copy and leaves no partial file behind', () => {
    const file = join(dir, 'aka.db');
    const db = openStore(file, 3);
    const backup = backupPath(file, 'legacy');
    snapshotStore(db, backup);
    db.close();

    const copy = new DatabaseSync(backup);
    const rows = copy.prepare('SELECT COUNT(*) AS n FROM corpus').get() as { n: number };
    copy.close();
    expect(rows.n).toBe(3);
    // A single materialized file — no sidecars, and the `.partial` it was
    // written as is gone.
    expect(readdirSync(dir).filter((f) => f.endsWith('.partial'))).toEqual([]);
    expect(existsSync(`${backup}-wal`)).toBe(false);
  });

  it('holds the copy at 0600, not the umask default', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    const backup = backupPath(file, 'legacy');
    snapshotStore(db, backup);
    db.close();
    expect(statSync(backup).mode & 0o777).toBe(0o600);
  });

  // VACUUM INTO FOLLOWS a symlink at its output path, and a dangling link passes
  // its "output file already exists" check — so a planted link sends the whole
  // prompt corpus to the link's target, at the umask, and tightenFile then
  // declines to chmod a link. Both paths involved have to be covered: the rename
  // protects `backup`, but `partial` is the path SQLite actually writes, and it
  // is derived from `backup`, so anyone who can plant at one can plant at the
  // other. `partial` is guarded by unlinking before the copy — unlink acts on
  // the link, never on its target.
  for (const plantedAt of ['backup', 'partial'] as const) {
    it(`does not write through a symlink planted at the ${plantedAt} path`, (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
        return;
      }
      const file = join(dir, 'aka.db');
      const db = openStore(file);
      const backup = backupPath(file, 'legacy');
      const target = join(dir, 'elsewhere.txt');
      symlinkSync(target, plantedAt === 'backup' ? backup : `${backup}.partial`);

      snapshotStore(db, backup);
      db.close();

      expect(existsSync(target)).toBe(false);
      expect(lstatSync(backup).isSymbolicLink()).toBe(false);
      expect(statSync(backup).mode & 0o777).toBe(0o600);
      expect(readdirSync(dir).filter((f) => f.endsWith('.partial'))).toEqual([]);
    });
  }

  it('leaves nothing behind when the copy fails', () => {
    // A corrupt page fails the copy partway. Neither the partial nor a
    // zero-length `.bak` may survive — either would read as a usable backup at
    // recovery time.
    const file = join(dir, 'aka.db');
    const seed = openStore(file, 200);
    seed.close();
    corruptStore(file, 'page');

    const db = new DatabaseSync(file);
    const backup = backupPath(file, 'legacy');
    expect(() => {
      snapshotStore(db, backup);
    }).toThrow();
    db.close();

    expect(existsSync(backup)).toBe(false);
    expect(readdirSync(dir).filter((f) => f.endsWith('.partial'))).toEqual([]);
  });
});

describe('moveStoreAside', () => {
  it('moves the -wal alongside the main file so the moved store reopens complete', (ctx) => {
    if (process.platform === 'win32') {
      // The repro holds a connection open across the move, and renaming an open
      // store file is a sharing violation on Windows.
      ctx.skip('a second open connection blocks renaming the store file on Windows');
      return;
    }
    // Renaming the main file alone strands committed frames in a -wal that no
    // longer pairs with it. SQLite derives the WAL name from the main filename,
    // so the sidecars move to matching names and the moved set reopens whole.
    const file = join(dir, 'aka.db');
    const writer = new DatabaseSync(file);
    writer.exec('PRAGMA journal_mode = WAL');
    writer.exec('PRAGMA wal_autocheckpoint = 0');
    writer.exec('CREATE TABLE corpus (id TEXT PRIMARY KEY)');
    writer.exec("INSERT INTO corpus (id) VALUES ('wal-only')");
    // A second connection held open ACROSS the move is what keeps the close from
    // checkpointing, so the schema and the row stay in the -wal and the sidecar
    // loop has something real to move. It must run a statement: SQLite does not
    // touch the file until one does, so a merely-constructed handle holds no read
    // mark and the writer's close would checkpoint and delete the -wal anyway.
    const holder = new DatabaseSync(file);
    holder.prepare('SELECT 1').get();
    writer.close();
    const backup = backupPath(file, 'legacy');
    // Assert the precondition rather than assume it — without a live -wal here
    // this test passes no matter what the sidecar loop does.
    expect(existsSync(`${file}-wal`)).toBe(true);

    try {
      moveStoreAside(file, backup);
    } finally {
      holder.close();
    }

    expect(existsSync(file)).toBe(false);
    expect(existsSync(`${file}-wal`)).toBe(false);
    expect(existsSync(`${backup}-wal`)).toBe(true);
    const moved = new DatabaseSync(backup);
    const rows = moved.prepare('SELECT id FROM corpus').all();
    moved.close();
    expect(rows).toEqual([{ id: 'wal-only' }]);
  });

  it('puts everything back when a sidecar can be neither moved nor removed', () => {
    // The real trigger is a live handle on Windows failing both the rename and
    // the remove. A directory standing in for the sidecar reproduces that pair
    // of failures on every platform without privileges: renaming a directory
    // onto an existing file is ENOTDIR, and rmSync without `recursive` refuses a
    // non-empty directory. Leaving the main file moved would hand the next open
    // a fresh store sitting beside a stale sidecar.
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    db.close();
    const before = readFileSync(file);
    const backup = backupPath(file, 'legacy');
    mkdirSync(`${file}-wal`);
    writeFileSync(join(`${file}-wal`, 'inner'), 'x');
    writeFileSync(`${backup}-wal`, 'occupied'); // makes the rename ENOTDIR

    expect(() => {
      moveStoreAside(file, backup);
    }).toThrow();

    // Rolled back: the store is exactly where it was, and nothing was published.
    expect(existsSync(backup)).toBe(false);
    expect(readFileSync(file)).toEqual(before);
    expect(existsSync(`${file}-wal`)).toBe(true);
  });

  it('preserves a store too damaged to copy, byte for byte', () => {
    const file = join(dir, 'aka.db');
    const seed = openStore(file, 200);
    seed.close();
    corruptStore(file, 'page');
    const before = readFileSync(file);

    const backup = backupPath(file, 'legacy');
    moveStoreAside(file, backup);

    expect(existsSync(file)).toBe(false);
    expect(readFileSync(backup)).toEqual(before);
  });

  it('does not leave the store half-moved when a sidecar rename fails but removal works', () => {
    // The ordinary degraded case: the sidecar cannot be renamed but can be
    // removed, so the move completes. Pinned alongside the rollback above so a
    // change to one cannot silently swap the two behaviours.
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    db.close();
    writeFileSync(`${file}-wal`, 'stale frames');
    const backup = backupPath(file, 'legacy');
    mkdirSync(`${backup}-wal`);
    writeFileSync(join(`${backup}-wal`, 'inner'), 'x'); // rename onto a non-empty dir fails

    try {
      moveStoreAside(file, backup);
    } finally {
      // Fixture cleanup: tightenPerms chmods every backup sidecar path to 0600,
      // and on the stand-in directory that strips the execute bit, which blocks
      // the recursive teardown. Real sidecars are files, where 0600 is the point.
      if (process.platform !== 'win32') chmodSync(`${backup}-wal`, 0o700);
    }

    expect(existsSync(file)).toBe(false);
    expect(existsSync(`${file}-wal`)).toBe(false); // removed, never left to be adopted
  });

  it('tightens the moved files to 0600', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes do not apply on Windows');
      return;
    }
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    db.close();
    chmodSync(file, 0o644); // the moved file keeps the source's mode

    const backup = backupPath(file, 'legacy');
    moveStoreAside(file, backup);
    expect(statSync(backup).mode & 0o777).toBe(0o600);
  });
});

describe('discardStore', () => {
  it('clears the store and its sidecars once the snapshot is published', () => {
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    db.close();
    writeFileSync(`${file}-wal`, 'stale');
    const backup = join(dir, 'aka.db.legacy.1.aaaaaaaa.bak');
    writeFileSync(backup, 'the snapshot');

    discardStore(file, backup);

    expect(existsSync(file)).toBe(false);
    expect(existsSync(`${file}-wal`)).toBe(false);
    expect(existsSync(backup)).toBe(true); // the reset happened; the copy is the point
  });

  it('drops the published backup when the store cannot be cleared', () => {
    // The real trigger is EBUSY/EPERM on Windows, where another process holds
    // the store open — `force` covers only a path that is already gone. A
    // non-empty directory reproduces a non-ENOENT failure on every platform
    // (rmSync refuses one without `recursive`), which is what the guard reacts
    // to. Without the guard the reset fails with a full-size copy of the store
    // orphaned beside it, once per attempt, and the plugin reopens on every
    // hook.
    const file = join(dir, 'aka.db');
    mkdirSync(file);
    writeFileSync(join(file, 'inner'), 'x');
    const backup = join(dir, 'aka.db.legacy.1.bbbbbbbb.bak');
    writeFileSync(backup, 'a full-size snapshot');

    expect(() => {
      discardStore(file, backup);
    }).toThrow();

    expect(existsSync(backup)).toBe(false); // no orphan left behind
    expect(existsSync(file)).toBe(true); // the original is untouched
  });
});
