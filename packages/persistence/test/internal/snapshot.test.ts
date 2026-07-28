import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { backupPath, moveStoreAside, snapshotStore } from '../../src/internal/snapshot.ts';
import { corruptStore } from '../helpers/fault-injection.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-snapshot-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** A real store with `rows` rows, left open. */
function openStore(file: string, rows = 1): DatabaseSync {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('CREATE TABLE corpus (id INTEGER PRIMARY KEY, v TEXT)');
  for (let i = 0; i < rows; i += 1) {
    db.prepare('INSERT INTO corpus (v) VALUES (?)').run(`prompt-${String(i)}`);
  }
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

  it('replaces a symlink at the backup path instead of writing through it', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // VACUUM INTO follows a symlink at its output path, and a dangling link
    // passes its "output file already exists" check — so writing the copy
    // directly would push the whole prompt corpus to the link's target, and
    // tightenFile would decline to chmod a link, leaving it at the umask. The
    // copy goes to an unguessable `.partial` and is renamed into place, and a
    // rename replaces the link itself.
    const file = join(dir, 'aka.db');
    const db = openStore(file);
    const backup = backupPath(file, 'legacy');
    const target = join(dir, 'elsewhere.txt');
    symlinkSync(target, backup);

    snapshotStore(db, backup);
    db.close();

    expect(existsSync(target)).toBe(false);
    expect(lstatSync(backup).isSymbolicLink()).toBe(false);
    expect(statSync(backup).mode & 0o777).toBe(0o600);
  });

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
  it('moves the -wal alongside the main file so the moved store reopens complete', () => {
    // Renaming the main file alone strands committed frames in a -wal that no
    // longer pairs with it. SQLite derives the WAL name from the main filename,
    // so the sidecars move to matching names and the moved set reopens whole.
    const file = join(dir, 'aka.db');
    const writer = new DatabaseSync(file);
    writer.exec('PRAGMA journal_mode = WAL');
    writer.exec('PRAGMA wal_autocheckpoint = 0');
    writer.exec('CREATE TABLE corpus (id TEXT PRIMARY KEY)');
    writer.exec("INSERT INTO corpus (id) VALUES ('wal-only')");
    // A second connection keeps the close from checkpointing, so the schema and
    // the row stay in the -wal.
    const holder = new DatabaseSync(file);
    writer.close();
    const backup = backupPath(file, 'legacy');
    holder.close();

    moveStoreAside(file, backup);

    expect(existsSync(file)).toBe(false);
    expect(existsSync(`${file}-wal`)).toBe(false);
    const moved = new DatabaseSync(backup);
    const rows = moved.prepare('SELECT id FROM corpus').all();
    moved.close();
    expect(rows).toEqual([{ id: 'wal-only' }]);
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
