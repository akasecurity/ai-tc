/**
 * Another process holding the store's write lock for longer than we will wait.
 *
 * This is the fault the product's architecture makes ordinary rather than
 * exotic: three processes share one file, `busy_timeout` is the entire
 * contention mitigation, and there is no retry or backoff anywhere behind it.
 * Past that timeout the write is simply dropped, and nothing counts it.
 *
 * Every contended write here costs a full `busy_timeout` (2 s for a
 * `LocalDatabase`), so the contended count per test is kept deliberately small.
 * A raw handle sets no `busy_timeout` at all and is refused immediately, which
 * is why the code-level assertions use one.
 */
import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { failOpenTransaction } from '../../src/internal/transactions.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { errorFrom } from '../helpers/errors.ts';
import { lockStore, primaryCode, SQLITE_BUSY } from '../helpers/fault-injection.ts';
import { useTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';

const store = useTempStore('aka-fault-locked-');

describe('a capture that loses the write lock', () => {
  it('drops the event silently — no throw, no row, no signal', async () => {
    const db = store.open();
    const seeded = captureEvent();
    db.recordCapture(seeded, [captureFinding(seeded.id)]);
    const before = (await db.findings.recentFindings()).length;

    // The victim's handle is opened first on purpose: `openLocalDatabase`
    // writes on the way in, so opening under a held lock fails outright rather
    // than reaching the write this case is about.
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
    const lost = captureEvent();
    const err = errorFrom(() => {
      db.recordCapture(lost, [captureFinding(lost.id)]);
    });
    lock.release();

    // Fail-open holds: the host session never learns anything went wrong.
    expect(err).toBeUndefined();
    // And this is the cost of it. The event is gone, and the store carries no
    // counter, no marker and no log line saying so — an audit trail with a
    // hole in it that reads exactly like one without.
    expect((await db.findings.recentFindings()).length).toBe(before);
  });

  it('keeps serving reads while the writer is locked out', async () => {
    const db = store.open();
    const seeded = captureEvent();
    db.recordCapture(seeded, [captureFinding(seeded.id)]);

    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
    // WAL gives readers a snapshot that a held write lock does not block, so
    // the dashboard and `aka stats` stay accurate about what the store already
    // holds while captures are being dropped.
    const health = await db.findings.healthSummary();
    lock.release();

    expect(health.findings).toBe(1);
  });

  it('records normally again as soon as the lock is gone', async () => {
    // The positive control: the drop above was the contention, not a store
    // this suite had already broken.
    const db = store.open();
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
    const lost = captureEvent();
    db.recordCapture(lost, [captureFinding(lost.id)]);
    lock.release();

    const kept = captureEvent();
    db.recordCapture(kept, [captureFinding(kept.id)]);
    expect((await db.findings.recentFindings()).length).toBe(1);
  });
});

describe('the SQLITE_BUSY fail-open branch', () => {
  it('names the failure as contention when the caller does not swallow it', () => {
    store.open().close();
    // A raw handle carries no `busy_timeout`, so it is refused at once instead
    // of waiting the 2 s a `LocalDatabase` would — the same code, without
    // paying for it.
    const raw = store.openRaw();
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

    const err = errorFrom(() => {
      raw.exec('BEGIN IMMEDIATE');
    });
    lock.release();

    expect(primaryCode(err)).toBe(SQLITE_BUSY);
  });

  it('is swallowed by the shared envelope, which reports only that nothing committed', () => {
    store.open().close();
    const raw = store.openRaw();
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

    const committed = failOpenTransaction(
      raw,
      () => {
        raw.exec('CREATE TABLE fault_probe (id INTEGER PRIMARY KEY)');
      },
      'IMMEDIATE',
    );
    lock.release();

    // Indistinguishable from a full disk, a read-only store, or a caller bug —
    // all four arrive here as `false`, and the four sites in `database.ts` that
    // call this discard it.
    expect(committed).toBe(false);
    assertNoOpenTransaction(raw);
  });
});

describe('opening a store whose write lock is held', () => {
  it('fails rather than blocking forever, because the open itself writes', () => {
    store.open().close();
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

    // `PRAGMA journal_mode = WAL`, the migration applier and the `ensure*`
    // passes all write, so a contended open is refused once `busy_timeout`
    // runs out. For a hook that means no gateway at all — which is the one
    // failure a caller can still turn into a message to the user.
    const err = errorFrom(() => openLocalDatabase(store.dataDir));
    lock.release();

    expect(err).toBeDefined();
    expect(primaryCode(err)).toBe(SQLITE_BUSY);
  });

  it('opens normally once the lock is released', () => {
    // The positive control for the refusal above.
    store.open().close();
    const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
    lock.release();

    const db = openLocalDatabase(store.dataDir);
    expect(db).toBeDefined();
    db.close();
  });
});
