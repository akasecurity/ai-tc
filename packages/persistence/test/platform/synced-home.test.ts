/**
 * The store in a home a sync client is watching — a OneDrive-redirected
 * `C:\Users\<name>` on Windows, an iCloud or Dropbox folder elsewhere. That is a
 * real user configuration rather than a hypothetical one, and it is the classic
 * way a WAL-mode SQLite database is silently rolled back.
 *
 * Three properties live here, and they fail differently:
 *
 * 1. **What journal mode the store ends up in.** `openWithPragmas` issues
 *    `PRAGMA journal_mode = WAL` and never reads the answer, so a filesystem
 *    that refuses WAL — a DrvFs path such as `/mnt/c` under WSL, some network
 *    mounts — leaves the store in a rollback mode with nothing reporting it.
 *    The capture path has to keep working there, because a hook that cannot
 *    write drops the event fail-open with no signal at all.
 *
 * 2. **What a sync client's copy actually contains.** In WAL mode everything
 *    since the last checkpoint — including the schema itself on a young store —
 *    lives in `aka.db-wal`, not in `aka.db`.
 *
 * 3. **That nothing in the data directory is left untightened**, in either
 *    journal mode. Which sidecars exist depends on the mode, so the at-rest
 *    claim has to hold across both, and the set is read off the directory
 *    rather than from a list.
 *
 * Every case runs on all three platforms. The mode assertions are the only ones
 * that branch: on Windows POSIX modes are a no-op and SECURITY.md carries the
 * honest answer instead. The rest is filesystem and locking behaviour, which is
 * exactly what running this on a non-Linux runner buys.
 */
import { copyFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { dbSidecars } from '../../src/paths.ts';
import { captureCount, captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { errorFrom } from '../helpers/errors.ts';
import type { TempStore } from '../helpers/temp-store.ts';
import { withTempStore } from '../helpers/temp-store.ts';

const MODE_BITS = 0o777;

/** The journal mode SQLite reports for a handle. */
function journalMode(db: DatabaseSync): string {
  return (db.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode;
}

/** Record `n` captures through the product path. */
function record(store: TempStore, n: number): void {
  const db = store.open();
  for (let i = 0; i < n; i += 1) {
    const event = captureEvent();
    db.recordCapture(event, [captureFinding(event.id)]);
  }
}

/** Read a copied store the way a user restoring a backup would. */
function withCopy(file: string, assert: (db: DatabaseSync) => void): void {
  const db = new DatabaseSync(file);
  try {
    assert(db);
  } finally {
    db.close();
  }
}

// -------------------------------------------------------------------------
// 1. The journal mode the store lands in
// -------------------------------------------------------------------------

describe('journal mode', () => {
  it('is WAL after the product opens the store', () => {
    // The positive control for everything below. Without it, a case asserting
    // "the rows are in the sidecar" could pass on a store that was never in WAL
    // mode at all, and the synced-copy hazard would read as absent.
    withTempStore((store) => {
      store.open();
      expect(journalMode(store.openRaw())).toBe('wal');
    });
  });

  it('records and reads back after a fall back to a rollback journal', () => {
    // The DrvFs/network-mount configuration, reached through the store's own
    // connection so the capture really runs in that mode. The `-wal` sidecar
    // goes away with the switch, which is the observable difference a sync
    // client's copy then sees.
    withTempStore((store) => {
      const db = store.open();
      const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
      expect(journalMode(raw)).toBe('wal');

      raw.exec('PRAGMA journal_mode = DELETE');
      expect(journalMode(raw)).toBe('delete');
      expect(existsSync(`${store.dbFile}-wal`)).toBe(false);

      const event = captureEvent();
      db.recordCapture(event, [captureFinding(event.id)]);
      expect(captureCount(raw)).toBe(1);
    });
  });

  it('takes a store left in a rollback mode back to WAL on the next open', () => {
    // A laptop that spent a session on a synced or network path comes back to a
    // local one. The PRAGMA runs on every open, so the mode is repaired rather
    // than inherited — and the rows written under the old mode survive it.
    withTempStore((store) => {
      const first = store.open();
      const event = captureEvent();
      first.recordCapture(event, [captureFinding(event.id)]);
      first[UNSAFE_TEST_ONLY_RAW_HANDLE].exec('PRAGMA journal_mode = DELETE');
      first.close();

      store.open();
      const reopened = store.openRaw();
      expect(journalMode(reopened)).toBe('wal');
      expect(captureCount(reopened)).toBe(1);
    });
  });
});

// -------------------------------------------------------------------------
// 2. What a sync client's copy contains
// -------------------------------------------------------------------------

describe('a sync client copying the store', () => {
  it('captures a store with no schema at all when it copies aka.db alone', () => {
    // The corruption source, reproduced — and it is worse than stale. On a
    // store young enough not to have checkpointed, the migrations themselves
    // are still in the sidecar, so a tool that copies the one file it
    // recognises and skips the ones that look like scratch carries an EMPTY
    // database. Nothing reports it: the copy opens cleanly and answers "no such
    // table" only when something reads it, which for a backup is years later.
    withTempStore((store) => {
      record(store, 5);
      const live = store.openRaw();
      expect(captureCount(live)).toBe(5);
      // Assert the frames are still in the sidecar rather than assume it. A
      // checkpoint here — a bigger write, a changed autocheckpoint threshold —
      // would make the copy complete and this case vacuous.
      expect(existsSync(`${store.dbFile}-wal`)).toBe(true);
      expect(statSync(`${store.dbFile}-wal`).size).toBeGreaterThan(0);

      const partial = join(store.dataDir, 'synced-copy.db');
      copyFileSync(store.dbFile, partial);

      withCopy(partial, (copied) => {
        const err = errorFrom(() => captureCount(copied));
        expect(err?.message).toMatch(/no such table/i);
      });
      // Nothing about the copy disturbed the live store.
      expect(captureCount(live)).toBe(5);
    });
  });

  it('carries everything when it copies the sidecar with it', () => {
    // The actionable half: a copy is a copy only if it takes `aka.db-wal` too.
    // `-shm` is rebuilt on open and deliberately is not part of this — a sync
    // client that carries it is not doing anything extra that helps.
    withTempStore((store) => {
      record(store, 5);
      expect(captureCount(store.openRaw())).toBe(5);

      const whole = join(store.dataDir, 'synced-whole.db');
      copyFileSync(store.dbFile, whole);
      copyFileSync(`${store.dbFile}-wal`, `${whole}-wal`);

      withCopy(whole, (copied) => {
        expect(captureCount(copied)).toBe(5);
      });
    });
  });

  it('captures a complete store once the journal mode has fallen back', () => {
    // The mirror image, and the reason the two hazards are not one hazard: in a
    // rollback mode there is no sidecar to miss, so the naive single-file copy
    // a sync client makes is suddenly correct. The exposure is a property of
    // the journal mode, not of the sync client.
    withTempStore((store) => {
      const db = store.open();
      db[UNSAFE_TEST_ONLY_RAW_HANDLE].exec('PRAGMA journal_mode = DELETE');
      for (let i = 0; i < 5; i += 1) {
        const event = captureEvent();
        db.recordCapture(event, [captureFinding(event.id)]);
      }

      const partial = join(store.dataDir, 'synced-rollback.db');
      copyFileSync(store.dbFile, partial);
      withCopy(partial, (copied) => {
        expect(captureCount(copied)).toBe(5);
      });
    });
  });
});

// -------------------------------------------------------------------------
// 3. What ends up beside the store, and whether it is tightened
// -------------------------------------------------------------------------

describe('the files a used store leaves in the data directory', () => {
  it('are the database and its sidecars — nothing else', () => {
    // Read off the directory rather than from a list, so a file SQLite or a
    // migration starts writing shows up here rather than shipping untightened.
    //
    // No `.bak` exemption, because this fixture produces none: the pre-drop
    // snapshot is taken only where the legacy drop would destroy rows, and a
    // store these three writes built has none. The exemption that used to sit
    // here matched nothing, which is the shape that rots in silence — it would
    // have gone on passing through a rename of the snapshot, or its removal
    // altogether. If a copy ever does land beside a store built this way, that
    // is a change worth failing on rather than waving through.
    withTempStore((store) => {
      record(store, 3);

      const entries = readdirSync(store.dataDir);
      // Positive control: the filter below is empty over an empty directory, so
      // on its own it passes just as well against a store nothing wrote.
      expect(entries).toContain('aka.db');

      const named = new Set(['aka.db', ...dbSidecars('aka.db')]);
      const unexpected = entries.filter((name) => !named.has(name));
      expect(unexpected).toEqual([]);
    });
  });

  it.skipIf(process.platform === 'win32')('are every one of them owner-only after real use', () => {
    // paths.test.ts pins tightenPerms against hand-made files. This pins the
    // product path: whatever a real capture actually created is 0600 by the
    // time the capture returns — the database, the sidecars its journal mode
    // produced, and the migration snapshot beside them.
    withTempStore((store) => {
      record(store, 3);

      const files = readdirSync(store.dataDir);
      // More than the database alone, or the loop below says nothing.
      expect(files.length).toBeGreaterThan(1);
      for (const name of files) {
        expect({ name, mode: statSync(join(store.dataDir, name)).mode & MODE_BITS }).toEqual({
          name,
          mode: 0o600,
        });
      }
    });
  });

  it.skipIf(process.platform === 'win32')('stay owner-only in a rollback journal mode too', () => {
    // The mode that a synced or network home actually produces. Its sidecar
    // is `-journal` rather than `-wal`/`-shm`, and it holds store content the
    // same way — SECURITY.md names all three for this reason.
    withTempStore((store) => {
      const db = store.open();
      db[UNSAFE_TEST_ONLY_RAW_HANDLE].exec('PRAGMA journal_mode = DELETE');
      const event = captureEvent();
      db.recordCapture(event, [captureFinding(event.id)]);

      for (const name of readdirSync(store.dataDir)) {
        expect({ name, mode: statSync(join(store.dataDir, name)).mode & MODE_BITS }).toEqual({
          name,
          mode: 0o600,
        });
      }
    });
  });

  it.skipIf(process.platform !== 'win32')('carry no mode protection on Windows', () => {
    // Not a gap being papered over: Node cannot apply POSIX modes here, so the
    // store inherits whatever ACL the directory carries and SECURITY.md says so
    // in as many words. Pinned as behaviour so the documented answer and the
    // code cannot drift apart — a build that suddenly reported 0600 here would
    // mean the bits are being synthesised rather than enforced, and the
    // honest documentation would silently become wrong.
    withTempStore((store) => {
      record(store, 3);
      expect(existsSync(store.dbFile)).toBe(true);
      expect(statSync(store.dbFile).mode & MODE_BITS).not.toBe(0o600);
    });
  });
});

// -------------------------------------------------------------------------
// 4. Concurrent writers, on whichever platform this is
// -------------------------------------------------------------------------

describe('two writers on a store in this filesystem', () => {
  it('both land their captures through the product open path', () => {
    // The store is shared by a hook, the CLI and the dashboard with nothing but
    // WAL and busy_timeout between them, and file locking is one of the things
    // that genuinely differs by OS. The concurrency suite covers the contended
    // shapes; this is the same property reached through the real home layout,
    // so a platform where two handles could not coexist
    // fails here rather than in a helper.
    withTempStore((store) => {
      const a = store.open();
      const b = store.open();
      const first = captureEvent();
      const second = captureEvent();
      a.recordCapture(first, [captureFinding(first.id)]);
      b.recordCapture(second, [captureFinding(second.id)]);

      expect(captureCount(store.openRaw())).toBe(2);
    });
  });

  it('keeps the surviving handle writable after its sibling closes', () => {
    // Windows holds an open file against deletion and rename, so a handle
    // closing under a live sibling is worth pinning there specifically: the
    // survivor must keep writing rather than inherit a half-released lock.
    withTempStore((store) => {
      // Both through store.open(): a handle opened by hand is untracked, so an
      // assertion throwing before `a.close()` would leave it open and teardown
      // could not remove the tree. The tracker records an early close, so
      // closing `a` here is still exactly one close.
      const a = store.open();
      const b = store.open();
      const first = captureEvent();
      a.recordCapture(first, [captureFinding(first.id)]);
      a.close();

      const second = captureEvent();
      b.recordCapture(second, [captureFinding(second.id)]);

      expect(captureCount(store.openRaw())).toBe(2);
    });
  });
});
