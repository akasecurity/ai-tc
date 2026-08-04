/**
 * A store the process may read but not write.
 *
 * `SQLITE_READONLY` is one of the result codes the package never inspects: the
 * fail-open paths swallow it exactly as they swallow a caller bug. So what is
 * worth pinning is not that the write fails — it is *where* the failure lands,
 * because that decides whether the user is ever told. The refusal is loud at
 * open and silent at write, and the two reach very different callers.
 */
import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { failOpenTransaction } from '../../src/internal/transactions.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { errorFrom } from '../helpers/errors.ts';
import { primaryCode, readOnlyStore, SQLITE_READONLY } from '../helpers/fault-injection.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-fault-readonly-');

describe('opening a read-only store', () => {
  it('refuses with SQLITE_READONLY rather than returning a half-open store', (ctx) => {
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }

    // Where this lands is not where the fault's name suggests. `PRAGMA
    // journal_mode = WAL` SUCCEEDS on an already-WAL store — it even mints the
    // -wal/-shm sidecars, at the db's own 0400 — and the refusal comes later,
    // out of `ensureWriteGateTrigger` inside `applyMigrations`, one of the
    // `ensure*` passes that run on every open. So the applier does run here.
    //
    // What matters is only that it is loud: `openLocalDatabase` is the one
    // place a caller can still decide to tell the user, and every caller that
    // swallows this instead is a session running with detection off.
    const err = errorFrom(() => openLocalDatabase(store.dataDir));

    expect(err).toBeDefined();
    expect(primaryCode(err)).toBe(SQLITE_READONLY);
  });

  it('keeps refusing across repeated attempts', (ctx) => {
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }

    // The shape a user produces by retrying: the hook fires again on the next
    // tool call, the dashboard request comes back. Each attempt must fail the
    // same way rather than drifting to a different code as the earlier ones
    // leave sidecars behind.
    //
    // Deliberately NOT a handle-leak assertion. `database.ts` does guard that
    // (`closeQuietly` on both throw paths), but nothing here can observe it:
    // POSIX lets an open handle be unlinked, and `temp-store.ts` SWALLOWS
    // EPERM/EBUSY/EACCES/ENOTEMPTY on win32 by design — so a leak would leave
    // this green on both platforms, and this case skips on Windows anyway.
    for (let i = 0; i < 5; i += 1) {
      expect(primaryCode(errorFrom(() => openLocalDatabase(store.dataDir)))).toBe(SQLITE_READONLY);
    }
  });

  it('reports SQLITE_READONLY, not SQLITE_READONLY_DIRECTORY, even with the data dir tightened too', (ctx) => {
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, {
      includeDir: true,
      onCleanup: store.onCleanup,
    });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }

    // A 0500 data dir would stop SQLite creating its -wal/-shm sidecars and
    // give the directory-flavoured refinement instead. It never gets that far:
    // `openLocalDatabase` calls `ensureDataDirSync` first, which chmods the
    // directory back to 0700 — an owner can always re-widen their own
    // directory — so by the time SQLite looks, only the file mode is left.
    // Anything asserting the directory refinement here would be asserting a
    // code the product cannot reach through this entry point.
    expect(primaryCode(errorFrom(() => openLocalDatabase(store.dataDir)))).toBe(SQLITE_READONLY);
  });

  it('changes nothing about the store — the schema it refused to open is intact', (ctx) => {
    const seeded = store.open();
    const ev = captureEvent();
    seeded.recordCapture(ev, [captureFinding(ev.id)]);
    seeded.close();

    const tags = (): string[] => {
      const raw = store.openRaw();
      try {
        return (
          raw.prepare('SELECT tag FROM migration_ledger ORDER BY tag').all() as {
            tag: string;
          }[]
        ).map((row) => row.tag);
      } finally {
        raw.close();
      }
    };
    const before = tags();
    expect(before.length).toBeGreaterThan(0);

    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }
    for (let i = 0; i < 3; i += 1)
      expect(primaryCode(errorFrom(() => openLocalDatabase(store.dataDir)))).toBe(SQLITE_READONLY);
    readOnly.restore();

    // The applier DOES run on a read-only store — it reaches
    // `ensureWriteGateTrigger` before anything refuses — so "the ledger is
    // untouched" is a claim about a pass that really executed, not one that
    // was skipped. It cannot record a tag it could not write.
    expect(tags()).toEqual(before);
    // And the store is still usable once the mode is lifted: the refused opens
    // left no half-applied schema for the next one to trip over.
    const reopened = store.open();
    expect(tags()).toEqual(before);
    reopened.close();
  });
});

// There is deliberately no "recordCapture fails open under a read-only store"
// case here, because there is no such state to reach: the mode does not deny an
// already-open handle (below), and a handle opened afterwards never exists — the
// open is refused first. A test that chmods and then asserts recordCapture did
// not throw would be asserting that a write which SUCCEEDED did not throw, and
// would stay green with the fail-open envelope removed entirely. `recordCapture`
// swallowing a real store failure is pinned by the contended case in
// `locked-store.test.ts`, which does reach it.
describe('writing through a handle when the store turns read-only underneath it', () => {
  it('keeps writing through an already-open handle: the mode is checked at open, not at write', async (ctx) => {
    // Worth writing down because it is the opposite of what the fault's name
    // suggests. A descriptor carries the permission it was opened with, so
    // chmod'ing the store out from under a live connection revokes nothing —
    // the hook that was already running finishes recording normally, and only
    // the NEXT process is refused. A read-only store therefore loses no data
    // from a session already in flight.
    const db = store.open();
    const seeded = captureEvent();
    db.recordCapture(seeded, [captureFinding(seeded.id)]);
    const before = (await db.findings.recentFindings()).length;

    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }
    const ev = captureEvent();
    db.recordCapture(ev, [captureFinding(ev.id)]);

    expect((await db.findings.recentFindings()).length).toBe(before + 1);
  });

  it('keeps serving reads', async (ctx) => {
    const db = store.open();
    const ev = captureEvent();
    db.recordCapture(ev, [captureFinding(ev.id)]);

    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }

    // The dashboard and `aka stats` are readers. Denying writes must not take
    // the read surfaces with it, or a store the user was told to leave alone
    // would also stop reporting what it already holds.
    expect((await db.findings.healthSummary()).findings).toBe(1);
  });

  it('opens and writes again once the mode is restored', async (ctx) => {
    // The positive control for every case above: the refusals were the mode,
    // and lifting it is enough to undo them. Not quite "nothing changed" — a
    // refused open mints -wal/-shm at the db's 0400, and this case passes only
    // because `readOnlyStore.restore()` widens those too (see the helper).
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }
    // Refused FIRST, then restored. Without this the case only shows that
    // applying and undoing the mode is a round trip — it would pass unchanged
    // against an injector that had stopped chmod'ing anything at all, which is
    // precisely the state it exists to rule out.
    expect(primaryCode(errorFrom(() => openLocalDatabase(store.dataDir)))).toBe(SQLITE_READONLY);
    readOnly.restore();

    const db = openLocalDatabase(store.dataDir);
    const ev = captureEvent();
    db.recordCapture(ev, [captureFinding(ev.id)]);
    expect((await db.findings.recentFindings()).length).toBe(1);
    db.close();
  });
});

describe('the SQLITE_READONLY fail-open branch', () => {
  it('swallows the refusal and reports it as a failed write', (ctx) => {
    // The branch the product actually takes, reached over a raw handle because
    // `LocalDatabase` opens its own connection and the mode has to be in place
    // before that open. `failOpenTransaction` is the shared envelope every
    // blanket fail-open site in `database.ts` uses, so this is that code path,
    // not a lookalike.
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }
    const raw = store.openRaw();

    const committed = failOpenTransaction(raw, () => {
      raw.exec('CREATE TABLE fault_probe (id INTEGER PRIMARY KEY)');
    });

    // `false` is the whole signal a caller gets. It does not say read-only, and
    // no caller in the package reads it — the four sites in `database.ts`
    // discard it. That is the documented behaviour, not an oversight this test
    // is asserting away.
    expect(committed).toBe(false);
    // The fault was contained: a transaction left open here would hold the
    // connection's locks and silently enrol every later write on it.
    expect(raw.isTransaction).toBe(false);
  });

  it('raises SQLITE_READONLY when the caller does not swallow it', (ctx) => {
    // The same write without the envelope, so the code the envelope is hiding
    // is named at least once. Without this the suite would pin only that
    // something failed.
    store.open().close();
    const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
    if (!readOnly.effective) {
      ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
      return;
    }
    const raw = store.openRaw();

    expect(
      primaryCode(
        errorFrom(() => {
          raw.exec('CREATE TABLE fault_probe (id INTEGER PRIMARY KEY)');
        }),
      ),
    ).toBe(SQLITE_READONLY);
  });
});
