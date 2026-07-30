import { existsSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { dbSidecars } from '../../src/paths.ts';
import {
  corruptStore,
  fillStore,
  lockStore,
  primaryCode,
  readOnlyStore,
  SQLITE_BUSY,
  SQLITE_CORRUPT,
  SQLITE_FULL,
  SQLITE_NOTADB,
  SQLITE_READONLY,
  SQLITE_READONLY_DIRECTORY,
  sqliteErrcode,
} from './fault-injection.ts';
import type { TempStore } from './temp-store.ts';
import { withTempStore } from './temp-store.ts';
import { assertNoOpenTransaction } from './transactions.ts';

// Each injector is asserted by the result code it produces, not by a message or
// a timing: the codes are what the store's error handling does not currently
// distinguish, and they are the reason these helpers exist. `primaryCode`
// asserts the class of failure; `sqliteErrcode` is for the cases where the
// extended refinement is itself the point.

/** Create and migrate the store, then let go of it — the file is left on disk. */
function seedStore(store: TempStore): void {
  const db = store.open();
  db.ruleProbeCache.setVerdict('seeded', 'safe', 1);
  db.close();
}

/** The errcode raised by a write on a fresh raw handle, or undefined if it worked. */
function attemptWrite(file: string, busyTimeoutMs = 250): number | undefined {
  let db: DatabaseSync | undefined;
  try {
    db = new DatabaseSync(file);
    db.exec(`PRAGMA busy_timeout = ${String(busyTimeoutMs)}`);
    db.exec('CREATE TABLE IF NOT EXISTS fault_probe (id INTEGER PRIMARY KEY)');
    db.exec('INSERT INTO fault_probe (id) VALUES (1)');
    return undefined;
  } catch (err) {
    return primaryCode(err);
  } finally {
    try {
      db?.close();
    } catch {
      // The failure above may already have torn the handle down.
    }
  }
}

const MODES_IGNORED =
  'this host ignores the mode change — a root process, or a filesystem without POSIX modes';

describe('sqliteErrcode / primaryCode', () => {
  it('reads the result code off a node:sqlite error', () => {
    withTempStore((store) => {
      seedStore(store);
      const db = store.openRaw();
      let err: unknown;
      try {
        db.exec('SELECT * FROM no_such_table');
      } catch (caught) {
        err = caught;
      } finally {
        // Windows will not delete a file another handle still holds, so a
        // handle a test opens is a handle a test closes.
        db.close();
      }
      expect(sqliteErrcode(err)).toBeTypeOf('number');
      expect(primaryCode(err)).toBeTypeOf('number');
    });
  });

  it('primaryCode strips the refinement an extended code carries', () => {
    // SQLITE_READONLY_DIRECTORY is SQLITE_READONLY with 6 in its high bits.
    // Asserting the class must not depend on which refinement SQLite picked.
    const err = Object.assign(new Error('readonly directory'), {
      errcode: SQLITE_READONLY_DIRECTORY,
    });
    expect(sqliteErrcode(err)).toBe(SQLITE_READONLY_DIRECTORY);
    expect(primaryCode(err)).toBe(SQLITE_READONLY);
  });

  it('both are undefined for anything that is not a node:sqlite error', () => {
    expect(sqliteErrcode(new Error('plain'))).toBeUndefined();
    expect(primaryCode(new Error('plain'))).toBeUndefined();
    expect(sqliteErrcode('not an error')).toBeUndefined();
    expect(primaryCode(undefined)).toBeUndefined();
  });
});

describe('corruptStore', () => {
  it('truncate: the header survives, the pages do not — SQLITE_CORRUPT', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'truncate', { store });

      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_CORRUPT);
    });
  });

  it('header: SQLite refuses the file outright — SQLITE_NOTADB', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'header', { store });

      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_NOTADB);
    });
  });

  it('page: the store still opens and reads — only integrity_check notices', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'page', { store });

      // The quiet failure: nothing throws, so a fail-open caller carries on.
      const db = store.openRaw();
      expect(() => db.prepare('SELECT count(*) AS n FROM rule_probe_cache').get()).not.toThrow();
      assertNoOpenTransaction(db);

      // What separates 'page' from the other two modes, as a result code rather
      // than a message: a full scan reaches the damaged page and raises
      // SQLITE_CORRUPT, where truncate and header never open at all. Asserting
      // `integrity_check !== 'ok'` here would only re-run corruptStore's own
      // postcondition, which it already refuses to return without.
      let err: unknown;
      try {
        db.prepare('PRAGMA integrity_check').all();
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_CORRUPT);
      db.close();
    });
  });

  it('changes the same bytes every run', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'page', { store });
      // A second flip at the same offset undoes the first, so the store reads
      // healthy again and the injector refuses to claim it damaged it.
      expect(() => {
        corruptStore(store.dbFile, 'page', { store });
      }).toThrow(/still reads as a healthy store/);
    });
  });

  it('clears the DB sidecars so they cannot replay over the damage', () => {
    withTempStore((store) => {
      seedStore(store);
      for (const sidecar of dbSidecars(store.dbFile)) {
        writeFileSync(sidecar, 'stale');
      }
      corruptStore(store.dbFile, 'truncate', { store });
      for (const sidecar of dbSidecars(store.dbFile)) {
        expect(existsSync(sidecar)).toBe(false);
      }
    });
  });

  it('refuses a store that is not there, or too small to damage as asked', () => {
    withTempStore((store) => {
      expect(() => {
        corruptStore(join(store.dataDir, 'absent.db'));
      }).toThrow(/no store at/);

      const tiny = join(store.home, 'tiny.db');
      writeFileSync(tiny, 'x'.repeat(64));
      expect(() => {
        corruptStore(tiny, 'truncate');
      }).toThrow(/write to the store first/);
    });
  });

  it('refuses to run while a handle is still open on the store', () => {
    withTempStore((store) => {
      seedStore(store);
      const live = store.open();
      // Removing the WAL from under a live connection makes the damage depend
      // on that connection's cached pages — the one thing this injector
      // promises not to do. Enforced, not just documented.
      expect(() => {
        corruptStore(store.dbFile, 'truncate', { store });
      }).toThrow(/still open/);

      live.close();
      expect(() => {
        corruptStore(store.dbFile, 'truncate', { store });
      }).not.toThrow();
    });
  });
});

describe('readOnlyStore', () => {
  it('refuses a store that is not there rather than reporting it effective', () => {
    withTempStore((store) => {
      seedStore(store);
      // An absent file tightens nothing, and `every` over nothing is true — so
      // without the guard this hands back `effective: true` for a store the
      // caller can freely write, which is the exact vacuous pass the helper
      // exists to prevent.
      expect(() => {
        readOnlyStore(join(store.dataDir, 'nope.db'), { onCleanup: store.onCleanup });
      }).toThrow(/no store at/);
    });
  });

  it('reports exactly whether the mode change denies writes', () => {
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });

      // The contract, asserted on every platform: `effective` is true when and
      // only when a write is actually refused. Windows ignores modes on
      // directories and a root process ignores them everywhere, so predicting
      // the value would be wrong — reporting it honestly is the point.
      expect(readOnly.effective).toBe(attemptWrite(store.dbFile) !== undefined);
    });
  });

  it('denies the write, on every platform', (ctx) => {
    // No platform guard: Node maps the write bit to the read-only attribute on
    // Windows too — only directory modes are the no-op there — and Windows is
    // the platform where the store has no other at-rest protection.
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
      if (!readOnly.effective) ctx.skip(MODES_IGNORED);

      expect(attemptWrite(store.dbFile)).toBeDefined();
      // No write bit anywhere, whatever the platform calls it.
      expect(statSync(store.dbFile).mode & 0o222).toBe(0);
    });
  });

  // Split from the case above rather than branched inside it: the mode
  // assertion is meaningless on Windows, which reports a read-only file as 0444
  // whatever was asked for, and which result code it raises for one is not
  // pinned. Branching would report the whole thing as a pass there.
  it('raises SQLITE_READONLY without widening the file to the world', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('Windows reports a read-only file as 0444 whatever mode was asked for');
    }
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
      if (!readOnly.effective) ctx.skip(MODES_IGNORED);

      expect(attemptWrite(store.dbFile)).toBe(SQLITE_READONLY);
      // 0400, not 0444: denying the write must not hand the prompt corpus to
      // every other account on the machine on the way.
      expect(statSync(store.dbFile).mode & 0o077).toBe(0);
    });
  });

  it('includeDir fails at open instead: WAL cannot create its sidecars', (ctx) => {
    if (process.platform === 'win32') ctx.skip('chmod is a no-op for directories on Windows');
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, {
        includeDir: true,
        onCleanup: store.onCleanup,
      });
      if (!readOnly.effective) ctx.skip(MODES_IGNORED);

      const db = store.openRaw();
      let err: unknown;
      try {
        db.exec('PRAGMA journal_mode = WAL');
      } catch (caught) {
        err = caught;
      } finally {
        db.close();
      }
      // The one place the refinement is the point: it names the directory, not
      // the file, as what SQLite could not write.
      expect(sqliteErrcode(err)).toBe(SQLITE_READONLY_DIRECTORY);
    });
  });

  it('openLocalDatabase widens the data dir again, so only the file mode bites', (ctx) => {
    if (process.platform === 'win32') ctx.skip('chmod is a no-op for directories on Windows');
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, {
        includeDir: true,
        onCleanup: store.onCleanup,
      });
      if (!readOnly.effective) ctx.skip(MODES_IGNORED);

      // ensureDataDirSync chmods the dir back to 0700 before SQLite opens the
      // file, so the directory fault never reaches the engine on this path.
      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_READONLY);
      expect(statSync(store.dataDir).mode & 0o777).toBe(0o700);
    });
  });

  it('restore() gives the modes back, and says so only once', () => {
    withTempStore((store) => {
      seedStore(store);
      const before = statSync(store.dbFile).mode & 0o7777;
      const readOnly = readOnlyStore(store.dbFile, { includeDir: true });
      readOnly.restore();
      readOnly.restore();

      expect(attemptWrite(store.dbFile)).toBeUndefined();
      // The exact bits, not just "writable again": the mode is captured with
      // `& 0o7777`, and restoring anything wider than the permission bits would
      // still let this write through.
      expect(statSync(store.dbFile).mode & 0o7777).toBe(before);
    });
  });
});

describe('lockStore', () => {
  it('a hold that outlasts busy_timeout makes the other writer fail with SQLITE_BUSY', () => {
    withTempStore((store) => {
      seedStore(store);
      lockStore(store.dbFile, { onCleanup: store.onCleanup });

      const victim = store.openRaw();
      victim.exec('PRAGMA busy_timeout = 250');
      let err: unknown;
      try {
        victim.exec('CREATE TABLE IF NOT EXISTS fault_probe (id INTEGER PRIMARY KEY)');
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_BUSY);
      // Losing the write must not leave the victim inside a transaction.
      assertNoOpenTransaction(victim);
      victim.close();
    });
  });

  it('a hold that ends inside busy_timeout lets the other writer through', () => {
    withTempStore((store) => {
      seedStore(store);
      // The lock is kept and released rather than left to expire on its own:
      // release() waits for the holder to close its handle, and on Windows the
      // tree cannot be removed while that handle is open.
      lockStore(store.dbFile, { holdMs: 150, onCleanup: store.onCleanup });
      // The victim waits out the hold rather than failing: this is the timeout
      // doing its job, and the reason the SQLITE_BUSY case above is a limit
      // rather than the normal outcome.
      expect(attemptWrite(store.dbFile, 5000)).toBeUndefined();
    });
  });

  it('locks a store that is not in WAL, and leaves its journal mode alone', () => {
    withTempStore((store) => {
      const seed = store.openRaw();
      seed.exec('PRAGMA journal_mode = delete');
      seed.exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
      seed.close();

      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
      // BEGIN IMMEDIATE takes a write lock in any journal mode, so the holder
      // has no reason to touch the mode — and every reason not to: the mode
      // change is the one statement busy_timeout cannot govern, and converting
      // the store is a side effect a fault injector must not have.
      expect(attemptWrite(store.dbFile, 250)).toBe(SQLITE_BUSY);
      lock.release();

      const after = store.openRaw();
      expect(
        (after.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode,
      ).toBe('delete');
      after.close();
    });
  });

  it('releases the lock, and does not mind being released twice', () => {
    withTempStore((store) => {
      seedStore(store);
      const lock = lockStore(store.dbFile);
      lock.release();
      lock.release();

      expect(attemptWrite(store.dbFile, 2000)).toBeUndefined();
    });
  });

  it('gives up loudly when the lock cannot be taken', () => {
    withTempStore((store) => {
      seedStore(store);
      lockStore(store.dbFile, { onCleanup: store.onCleanup });
      // busyTimeoutMs is what makes the second holder give up quickly;
      // readyTimeoutMs stays generous so a slow worker start can never be
      // mistaken for a lock it could not take.
      expect(() => lockStore(store.dbFile, { readyTimeoutMs: 10_000, busyTimeoutMs: 100 })).toThrow(
        /could not take the write lock/,
      );
    });
  });
});

// What the injectors do to the package, rather than to node:sqlite. Both of
// these cost a full busy_timeout (2000 ms) by construction — that is the
// measurement, not an accident of the test.
describe('lockStore against the product write path', () => {
  it('openLocalDatabase cannot open under a held lock: open the writers first', () => {
    withTempStore((store) => {
      seedStore(store);
      lockStore(store.dbFile, { onCleanup: store.onCleanup });

      // Opening is itself a write — the WAL pragma, then the migration and
      // ensure* passes — so a handle taken after the lock does not merely
      // block, it fails. withWriters opens up front for exactly this reason.
      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(primaryCode(err)).toBe(SQLITE_BUSY);
    });
  });

  it('a LocalDatabase write under the lock is dropped in silence, not raised', () => {
    withTempStore((store) => {
      const db = store.open();
      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

      // The behaviour the fail-open contract produces today, pinned so a change
      // to it is a decision: failOpenTransaction swallows the SQLITE_BUSY, so
      // the caller is told nothing and the event is simply gone.
      expect(() => {
        db.ruleProbeCache.setVerdict('lost-to-contention', 'safe', 1);
      }).not.toThrow();
      expect(db.ruleProbeCache.getVerdict('lost-to-contention')).toBeUndefined();

      // And the handle survives it: the swallowed failure left no transaction
      // open, so the next write once the lock is gone still lands.
      lock.release();
      db.ruleProbeCache.setVerdict('after-contention', 'safe', 2);
      expect(db.ruleProbeCache.getVerdict('after-contention')).toEqual({
        verdict: 'safe',
        worstProbeMs: 2,
      });
    });
  });
});

describe('fillStore', () => {
  it('raises SQLITE_FULL from the engine, leaving the store intact', () => {
    withTempStore((store) => {
      seedStore(store);
      const db = store.openRaw();
      db.exec('PRAGMA journal_mode = WAL');
      db.exec('CREATE TABLE bulk (id INTEGER PRIMARY KEY, v TEXT)');
      // Autocommit is required here, unlike the sibling test below: this asserts
      // that the rows committed BEFORE the cap was reached survive it, and one
      // wrapping transaction would roll every one of them back. So the cost has
      // to be bounded by the number of commits instead.
      //
      // Each row is sized to consume a whole page, so the cap is reached in
      // `headroomPages` writes rather than the ~40 that 200-byte rows took —
      // and, more to the point, the loop can never run away. Every iteration is
      // its own WAL commit, which the sibling below measured at tens of seconds
      // for 500 of them on the Windows runner; the old 20_000 bound was three
      // orders of magnitude past that, so any platform where SQLITE_FULL
      // arrived later than it does here blew the 20s budget and reported a
      // timeout instead of the assertion that would have explained it.
      const filled = fillStore(db, { headroomPages: 8 });
      const pageSize = (db.prepare('PRAGMA page_size').get() as { page_size: number }).page_size;

      const insert = db.prepare('INSERT INTO bulk (v) VALUES (?)');
      const payload = 'x'.repeat(pageSize);
      let written = 0;
      let err: unknown;
      try {
        // Comfortably above the 8 writes the headroom allows, so a platform that
        // fills later still fails on the result code below rather than the clock.
        for (let i = 0; i < 64; i += 1) {
          insert.run(payload);
          written += 1;
        }
      } catch (caught) {
        err = caught;
      }

      expect(primaryCode(err)).toBe(SQLITE_FULL);
      expect(written).toBeGreaterThan(0);
      // Out of room is not the same as damaged: every committed row is still
      // there, nothing was left half-written, and no transaction stayed open.
      expect((db.prepare('SELECT count(*) AS n FROM bulk').get() as { n: number }).n).toBe(written);
      expect(db.prepare('PRAGMA integrity_check').get()).toEqual({ integrity_check: 'ok' });
      assertNoOpenTransaction(db);

      filled.restore();
      expect(() => {
        insert.run(payload);
      }).not.toThrow();
      db.close();
    });
  });

  it('caps the handle it was given, not the file', () => {
    withTempStore((store) => {
      seedStore(store);
      const capped = store.openRaw();
      capped.exec('PRAGMA journal_mode = WAL');
      capped.exec('CREATE TABLE bulk (id INTEGER PRIMARY KEY, v TEXT)');
      fillStore(capped);

      const other = store.openRaw();
      const insert = other.prepare('INSERT INTO bulk (v) VALUES (?)');
      const payload = 'x'.repeat(200);
      // One transaction, not one per row: in autocommit each row is its own WAL
      // commit, and 500 of those runs for tens of seconds on the Windows runner.
      // The point is that this handle grows past the other's cap, not how many
      // commits it takes to get there.
      expect(() => {
        other.exec('BEGIN');
        for (let i = 0; i < 500; i += 1) insert.run(payload);
        other.exec('COMMIT');
      }).not.toThrow();

      other.close();
      capped.close();
    });
  });
});
