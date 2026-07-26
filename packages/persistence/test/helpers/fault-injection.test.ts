import { existsSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { walSidecars } from '../../src/paths.ts';
import {
  corruptStore,
  fillStore,
  lockStore,
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

// Each injector is asserted by the extended result code it produces, not by a
// message or a timing: the codes are what the store's error handling does not
// currently distinguish, and they are the reason these helpers exist.

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
    return sqliteErrcode(err);
  } finally {
    try {
      db?.close();
    } catch {
      // The failure above may already have torn the handle down.
    }
  }
}

function integrityOf(file: string): string | undefined {
  const db = new DatabaseSync(file);
  try {
    return (db.prepare('PRAGMA integrity_check').get() as { integrity_check?: string })
      .integrity_check;
  } finally {
    db.close();
  }
}

describe('sqliteErrcode', () => {
  it('reads the extended result code off a node:sqlite error', () => {
    withTempStore((store) => {
      seedStore(store);
      let err: unknown;
      try {
        new DatabaseSync(store.dbFile).exec('SELECT * FROM no_such_table');
      } catch (caught) {
        err = caught;
      }
      expect(sqliteErrcode(err)).toBeTypeOf('number');
    });
  });

  it('is undefined for anything that is not a node:sqlite error', () => {
    expect(sqliteErrcode(new Error('plain'))).toBeUndefined();
    expect(sqliteErrcode('not an error')).toBeUndefined();
    expect(sqliteErrcode(undefined)).toBeUndefined();
  });
});

describe('corruptStore', () => {
  it('truncate: the header survives, the pages do not — SQLITE_CORRUPT', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'truncate');

      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(sqliteErrcode(err)).toBe(SQLITE_CORRUPT);
    });
  });

  it('header: SQLite refuses the file outright — SQLITE_NOTADB', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'header');

      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(sqliteErrcode(err)).toBe(SQLITE_NOTADB);
    });
  });

  it('page: the store still opens and reads — only integrity_check notices', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'page');

      // The quiet failure: nothing throws, so a fail-open caller carries on.
      const db = new DatabaseSync(store.dbFile);
      expect(() => db.prepare('SELECT count(*) AS n FROM rule_probe_cache').get()).not.toThrow();
      db.close();

      expect(integrityOf(store.dbFile)).not.toBe('ok');
    });
  });

  it('changes the same bytes every run', () => {
    withTempStore((store) => {
      seedStore(store);
      corruptStore(store.dbFile, 'page');
      // A second flip at the same offset undoes the first, so the store reads
      // healthy again and the injector refuses to claim it damaged it.
      expect(() => {
        corruptStore(store.dbFile, 'page');
      }).toThrow(/still reads as a healthy store/);
      expect(integrityOf(store.dbFile)).toBe('ok');
    });
  });

  it('clears the WAL sidecars so they cannot replay over the damage', () => {
    withTempStore((store) => {
      seedStore(store);
      for (const sidecar of walSidecars(store.dbFile)) {
        writeFileSync(sidecar, 'stale');
      }
      corruptStore(store.dbFile, 'truncate');
      for (const sidecar of walSidecars(store.dbFile)) {
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
});

describe('readOnlyStore', () => {
  it('reports exactly whether the mode change denies writes', () => {
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile);
      store.onCleanup(() => {
        readOnly.restore();
      });

      // The contract, asserted on every platform: `effective` is true when and
      // only when a write is actually refused. Windows ignores modes on
      // directories and a root process ignores them everywhere, so predicting
      // the value would be wrong — reporting it honestly is the point.
      expect(readOnly.effective).toBe(attemptWrite(store.dbFile) !== undefined);
    });
  });

  it('a write to a read-only store raises SQLITE_READONLY', () => {
    if (process.platform === 'win32') return;
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile);
      store.onCleanup(() => {
        readOnly.restore();
      });
      if (!readOnly.effective) return;

      expect(attemptWrite(store.dbFile)).toBe(SQLITE_READONLY);
    });
  });

  it('includeDir fails at open instead: WAL cannot create its sidecars', () => {
    if (process.platform === 'win32') return;
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { includeDir: true });
      store.onCleanup(() => {
        readOnly.restore();
      });
      if (!readOnly.effective) return;

      let err: unknown;
      try {
        new DatabaseSync(store.dbFile).exec('PRAGMA journal_mode = WAL');
      } catch (caught) {
        err = caught;
      }
      expect(sqliteErrcode(err)).toBe(SQLITE_READONLY_DIRECTORY);
    });
  });

  it('openLocalDatabase widens the data dir again, so only the file mode bites', () => {
    if (process.platform === 'win32') return;
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { includeDir: true });
      store.onCleanup(() => {
        readOnly.restore();
      });
      if (!readOnly.effective) return;

      // ensureDataDirSync chmods the dir back to 0700 before SQLite opens the
      // file, so the directory fault never reaches the engine on this path.
      let err: unknown;
      try {
        openLocalDatabase(store.dataDir);
      } catch (caught) {
        err = caught;
      }
      expect(sqliteErrcode(err)).toBe(SQLITE_READONLY);
      expect(statSync(store.dataDir).mode & 0o777).toBe(0o700);
    });
  });

  it('restore() gives the modes back, and says so only once', () => {
    withTempStore((store) => {
      seedStore(store);
      const readOnly = readOnlyStore(store.dbFile, { includeDir: true });
      readOnly.restore();
      readOnly.restore();

      expect(attemptWrite(store.dbFile)).toBeUndefined();
    });
  });
});

describe('lockStore', () => {
  it('a hold that outlasts busy_timeout makes the other writer fail with SQLITE_BUSY', () => {
    withTempStore((store) => {
      seedStore(store);
      const lock = lockStore(store.dbFile);
      try {
        expect(attemptWrite(store.dbFile, 250)).toBe(SQLITE_BUSY);
      } finally {
        lock.release();
      }
    });
  });

  it('a hold that ends inside busy_timeout lets the other writer through', () => {
    withTempStore((store) => {
      seedStore(store);
      lockStore(store.dbFile, { holdMs: 150 });
      // The victim waits out the hold rather than failing: this is the timeout
      // doing its job, and the reason the SQLITE_BUSY case above is a limit
      // rather than the normal outcome.
      expect(attemptWrite(store.dbFile, 5000)).toBeUndefined();
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
      const held = lockStore(store.dbFile);
      try {
        // busyTimeoutMs is what makes the second holder give up quickly;
        // readyTimeoutMs stays generous so a slow worker start can never be
        // mistaken for a lock it could not take.
        expect(() =>
          lockStore(store.dbFile, { readyTimeoutMs: 10_000, busyTimeoutMs: 100 }),
        ).toThrow(/could not take the write lock/);
      } finally {
        held.release();
      }
    });
  });
});

describe('fillStore', () => {
  it('raises SQLITE_FULL from the engine, leaving the store intact', () => {
    withTempStore((store) => {
      seedStore(store);
      const db = new DatabaseSync(store.dbFile);
      db.exec('PRAGMA journal_mode = WAL');
      db.exec('CREATE TABLE bulk (id INTEGER PRIMARY KEY, v TEXT)');
      const filled = fillStore(db);

      const insert = db.prepare('INSERT INTO bulk (v) VALUES (?)');
      const payload = 'x'.repeat(200);
      let written = 0;
      let err: unknown;
      try {
        for (let i = 0; i < 20_000; i += 1) {
          insert.run(payload);
          written += 1;
        }
      } catch (caught) {
        err = caught;
      }

      expect(sqliteErrcode(err)).toBe(SQLITE_FULL);
      expect(written).toBeGreaterThan(0);
      // Out of room is not the same as damaged: every committed row is still
      // there and nothing was left half-written.
      expect((db.prepare('SELECT count(*) AS n FROM bulk').get() as { n: number }).n).toBe(written);
      expect(db.prepare('PRAGMA integrity_check').get()).toEqual({ integrity_check: 'ok' });

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
      const capped = new DatabaseSync(store.dbFile);
      capped.exec('PRAGMA journal_mode = WAL');
      capped.exec('CREATE TABLE bulk (id INTEGER PRIMARY KEY, v TEXT)');
      fillStore(capped);

      const other = new DatabaseSync(store.dbFile);
      const insert = other.prepare('INSERT INTO bulk (v) VALUES (?)');
      const payload = 'x'.repeat(200);
      expect(() => {
        for (let i = 0; i < 500; i += 1) insert.run(payload);
      }).not.toThrow();

      other.close();
      capped.close();
    });
  });
});
