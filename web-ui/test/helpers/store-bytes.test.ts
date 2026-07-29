import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { DB_FILENAME } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { storeBytes } from './store-bytes.ts';

// `storeBytes` is the at-rest leak scanner `test/actions/exceptions.test.ts`
// asserts through — `expect(storeBytes(dir)).not.toContain(rawValue)`. A reader
// that looked in too few places, or that swallowed its own failure, would leave
// every one of those assertions green while checking nothing. That is the
// failure mode this file exists to remove, so the reader gets its own tests.
//
// No real store is opened here, deliberately: these pin the READER. Pinning it
// against a store that actually received a write is the other suite's job, and
// it does that with a positive control — assert a value that IS expected on disk
// before asserting the raw is absent. Staying off `openLocalDatabase` also keeps
// this file off the per-test store-seeding hook (migrations, five `ensure*`
// passes, `seedDefaults`, 19 repository constructions, plus a full
// `recordInventory`) that dominates the other suite's per-test cost on the
// Windows runner.

// A 0o000 chmod is advisory: root writes straight through it, and Windows has no
// POSIX mode bits at all. Where the privilege or the platform decides instead of
// the test, skip — an early `return` would report as a pass.
const MODES_IGNORED =
  'the platform or the privilege ignores 0o000 — Windows ACLs, or running as root';

// A reader that fails on one name and delegates for the rest, so the fault
// branches are reachable where a real filesystem cannot be made to produce them.
function readerFailingOn(target: string, code: string): (path: string) => Buffer {
  return (path) => {
    if (basename(path) === target) {
      throw Object.assign(new Error(`${code}: injected, open '${path}'`), { code });
    }
    return readFileSync(path);
  };
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-web-store-bytes-'));
  writeFileSync(join(dir, DB_FILENAME), 'main-db-marker');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('storeBytes — the at-rest leak scanner', () => {
  it('reads every file in the data dir, not a hardcoded sidecar list', () => {
    // `aka.db-journal` is what SQLite writes instead of the `-wal`/`-shm` pair
    // in the rollback modes it falls back to where WAL silently no-ops, and a
    // `.bak` copy is left by a migration drop or the foreign-lineage reset. On
    // such a setup a WAL-only scan reports clean while the raw sits in a file it
    // never opened.
    //
    // These are planted files, not a store genuinely running in rollback mode:
    // `openLocalDatabase` always sets WAL and nothing in this repo can force
    // DELETE/TRUNCATE journalling, so what is pinned here is that the READER
    // covers the path. How the product behaves on such a mount stays untested.
    const planted: Record<string, string> = {
      'aka.db-wal': 'wal-marker',
      'aka.db-journal': 'rollback-journal-marker',
      'aka.db.pre-drop.1.bak': 'pre-drop-backup-marker',
      'aka.db.legacy.1.bak': 'foreign-lineage-backup-marker',
      'exception.key': 'key-file-marker',
    };
    for (const [name, marker] of Object.entries(planted)) {
      writeFileSync(join(dir, name), marker);
    }

    const bytes = storeBytes(dir);
    expect(bytes).toContain('main-db-marker');
    for (const marker of Object.values(planted)) expect(bytes).toContain(marker);
  });

  it('throws rather than reporting clean when the store is not where it expects', () => {
    // An empty read contains no secret, so a scanner that swallowed a missing
    // store would turn every `not.toContain` in the caller into a silent pass.
    //
    // Point it at another directory rather than moving `aka.db` aside: that is
    // the real failure shape (a layout change, or a broken `homedir()` mock
    // resolving somewhere else), and it needs no rename — which Windows refuses
    // while any handle on the file is still open, and these suites are in the
    // Windows CI leg.
    const elsewhere = mkdtempSync(join(tmpdir(), 'aka-web-store-bytes-empty-'));
    try {
      expect(() => storeBytes(elsewhere)).toThrow(/not reading the real store/);
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('rethrows a real permission denial on the main DB', (ctx) => {
    // The same property as the injected cases below, but against the actual
    // filesystem: `aka.db` is listed, so the presence check passes, and the
    // failure is in the open. Swallowing it would return the sidecar alone —
    // which carries none of the raw, so the caller reports clean.
    writeFileSync(join(dir, 'aka.db-wal'), 'wal-marker');
    const db = join(dir, DB_FILENAME);
    try {
      chmodSync(db, 0o000);
    } catch {
      ctx.skip(MODES_IGNORED);
    }
    let readable = true;
    try {
      readFileSync(db);
    } catch {
      readable = false;
    }
    if (readable) ctx.skip(MODES_IGNORED);

    try {
      // The open failure itself, not the missing-store message — different
      // faults, and only this one proves the read is unguarded.
      expect(() => storeBytes(dir)).toThrow(/EACCES|EPERM/);
    } finally {
      chmodSync(db, 0o600);
    }
  });

  it('rethrows a failed read on every platform, not only where chmod bites', () => {
    // The case above skips on Windows and under root. Windows is where a
    // sharing violation on an open store file is most likely, so the branch
    // cannot be pinned only where a real denial is easy to provoke.
    writeFileSync(join(dir, 'aka.db-wal'), 'wal-marker');
    expect(() => storeBytes(dir, readerFailingOn(DB_FILENAME, 'EBUSY'))).toThrow(/EBUSY/);
    expect(() => storeBytes(dir, readerFailingOn('aka.db-wal', 'EACCES'))).toThrow(/EACCES/);
  });

  it('rethrows even ENOENT when it is the main DB that vanished', () => {
    // `aka.db` is never atomically rewritten, so it has no legitimate reason to
    // disappear mid-scan. Folding it into the tolerance below would let the one
    // file that carries the store's contents go missing silently.
    expect(() => storeBytes(dir, readerFailingOn(DB_FILENAME, 'ENOENT'))).toThrow(/ENOENT/);
  });

  it('tolerates a sibling that vanished between the listing and the read', () => {
    // The one fault that must not propagate: an atomic write's per-process
    // `${file}.<pid>.tmp` is unlinked the moment it renames into place, so a
    // scan racing one legitimately sees ENOENT on an entry it just listed. The
    // rest of the directory must still be returned — a throw here would make
    // the caller flaky rather than safe.
    writeFileSync(join(dir, `${DB_FILENAME}.1234.tmp`), 'half-written');
    writeFileSync(join(dir, 'exception.key'), 'key-file-marker');

    const bytes = storeBytes(dir, readerFailingOn(`${DB_FILENAME}.1234.tmp`, 'ENOENT'));
    expect(bytes).toContain('main-db-marker');
    expect(bytes).toContain('key-file-marker');
  });
});
