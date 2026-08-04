/**
 * A store with no room left to grow.
 *
 * `SQLITE_FULL` is the fault where "fail-open" and "no corruption" are two
 * different claims: the write is allowed to vanish, but it must vanish WHOLE.
 * A transaction that committed half its rows would leave an audit event with
 * no findings, or findings pointing at an event that is not there — a store
 * that reads as healthy while telling a lie.
 *
 * `fillStore` caps growth on the connection it is handed, so these drive the
 * real repositories and the real shared envelopes over a raw handle. That is
 * as far as the fault reaches today: `openLocalDatabase` opens a connection of
 * its own and exposes no accessor for it, so the four blanket fail-open
 * closures in `database.ts` cannot be capped from a test. They take the same
 * `failOpenTransaction` path pinned below.
 */
import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { AuditEventInput } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { failOpenTransaction } from '../../src/internal/transactions.ts';
import { applyMigrations } from '../../src/migrations.ts';
import { SqliteAuditEventsRepository } from '../../src/repositories/audit-events.ts';
import { errorFrom } from '../helpers/errors.ts';
import { fillStore, primaryCode, SQLITE_FULL } from '../helpers/fault-injection.ts';
import { useTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';

const store = useTempStore('aka-fault-diskfull-');

/** Big enough that a capped store runs out inside a bounded number of rows. */
const PAGE_HUNGRY_CONTENT = 'x'.repeat(4096);
/** More rows than the cap can take, so the run is bounded by the fault. */
const MORE_ROWS_THAN_FIT = 4000;

function auditEvent(): AuditEventInput {
  return {
    id: randomUUID(),
    eventType: 'prompt',
    startedAt: new Date().toISOString(),
    content: PAGE_HUNGRY_CONTENT,
  };
}

function countAuditEvents(db: DatabaseSync): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM audit_events').get() as { n: number }).n;
}

function integrityOf(db: DatabaseSync): string | undefined {
  return (db.prepare('PRAGMA integrity_check').get() as { integrity_check?: string } | undefined)
    ?.integrity_check;
}

/**
 * Write audit events through the repository's own transaction envelope until
 * the capped store refuses, and return the error it refused with.
 *
 * `runInTransaction` wraps the whole batch in one `withTransaction`, which is
 * the shape the reconcile pass really uses — so this is the production path,
 * not a lookalike. Kept in one place because the row size and count are a
 * budget that has needed retuning for slower runners before, and four copies
 * of it would drift.
 */
function writeUntilFull(auditEvents: SqliteAuditEventsRepository): Error | undefined {
  return errorFrom(() => {
    auditEvents.runInTransaction(() => {
      for (let i = 0; i < MORE_ROWS_THAN_FIT; i += 1) auditEvents.insertAuditEvent(auditEvent());
    });
  });
}

describe('a repository write that runs the store out of room', () => {
  it('raises SQLITE_FULL and rolls the whole batch back, leaving no partial rows', () => {
    store.open().close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);
    const before = countAuditEvents(raw);

    const filled = fillStore(raw);
    const err = writeUntilFull(auditEvents);
    filled.restore();

    expect(primaryCode(err)).toBe(SQLITE_FULL);
    // The claim that matters: not one row of the batch survived. A partial
    // commit here is indistinguishable from a healthy store on every read.
    expect(countAuditEvents(raw)).toBe(before);
  });

  it('leaves no transaction open on the handle', () => {
    store.open().close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);

    const filled = fillStore(raw);
    expect(writeUntilFull(auditEvents)).toBeDefined();
    filled.restore();

    // A transaction left behind by the fault is worse than the fault: the
    // connection keeps its locks and every later write on it silently joins a
    // transaction nobody started.
    assertNoOpenTransaction(raw);
  });

  it('leaves the store consistent, and writable again once there is room', () => {
    store.open().close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);

    const filled = fillStore(raw);
    expect(writeUntilFull(auditEvents)).toBeDefined();

    expect(integrityOf(raw)).toBe('ok');
    filled.restore();

    // The positive control: the refusals above were the cap, not something
    // permanent this fault did to the store.
    const before = countAuditEvents(raw);
    auditEvents.insertAuditEvent({
      id: randomUUID(),
      eventType: 'prompt',
      startedAt: new Date().toISOString(),
    });
    expect(countAuditEvents(raw)).toBe(before + 1);
  });

  it('leaves a store a fresh process can still open and read', () => {
    const db = store.open();
    db.close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);

    const filled = fillStore(raw);
    expect(writeUntilFull(auditEvents)).toBeDefined();
    filled.restore();
    raw.close();

    // The cap belongs to the connection that set it, so a new one starts with
    // the store as it was left. Anything short of a clean open here would mean
    // the rollback had damaged the file rather than undone the write.
    expect(
      errorFrom(() => {
        store.open().close();
      }),
    ).toBeUndefined();
    const reader = store.openRaw();
    try {
      expect(integrityOf(reader)).toBe('ok');
    } finally {
      reader.close();
    }
  });
});

describe('the SQLITE_FULL fail-open branch', () => {
  it('swallows the failure and reports only that nothing committed', () => {
    store.open().close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);
    const before = countAuditEvents(raw);

    const filled = fillStore(raw);
    const committed = failOpenTransaction(raw, () => {
      for (let i = 0; i < MORE_ROWS_THAN_FIT; i += 1) auditEvents.insertAuditEvent(auditEvent());
    });
    filled.restore();

    // A full disk and a caller bug are the same `false` here — the store never
    // inspects the code, so nothing downstream can tell them apart or count
    // them. Documented, not asserted away.
    expect(committed).toBe(false);
    expect(countAuditEvents(raw)).toBe(before);
    assertNoOpenTransaction(raw);
  });

  it('rethrows while nested, because this failure takes the caller’s whole transaction with it', () => {
    store.open().close();
    const raw = store.openRaw();
    const auditEvents = new SqliteAuditEventsRepository(raw);

    const filled = fillStore(raw);
    raw.exec('BEGIN');
    // A nested envelope normally unwinds to its SAVEPOINT and returns `false`.
    // SQLITE_FULL is one of the failures SQLite resolves by rolling back the
    // whole transaction, savepoint included — so swallowing it would leave the
    // caller issuing durable autocommit statements it believes are still
    // guarded, and finding out only at a COMMIT that throws.
    const err = errorFrom(() =>
      failOpenTransaction(raw, () => {
        for (let i = 0; i < MORE_ROWS_THAN_FIT; i += 1) auditEvents.insertAuditEvent(auditEvent());
      }),
    );
    filled.restore();

    expect(primaryCode(err)).toBe(SQLITE_FULL);
    // Not the envelope's doing: the transaction was already gone when it
    // regained control, which is exactly what it keys the rethrow on.
    expect(raw.isTransaction).toBe(false);
  });
});

describe('running out of room mid-migration', () => {
  it('applies no migration at all rather than half of one', () => {
    // The applier runs its DDL statement by statement and stamps a ledger tag
    // per migration. A tag recorded for DDL that did not land is the worst
    // outcome available here: every later open reads the tag, skips the
    // migration, and meets a schema that never got built.
    const raw = store.openRaw();
    const filled = fillStore(raw);

    const err = errorFrom(() => {
      applyMigrations(raw, store.dbFile);
    });
    filled.restore();

    expect(primaryCode(err)).toBe(SQLITE_FULL);
    assertNoOpenTransaction(raw);

    const tags = raw
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'migration_ledger'")
      .all() as { name: string }[];
    const recorded =
      tags.length === 0
        ? []
        : (raw.prepare('SELECT tag FROM migration_ledger').all() as { tag: string }[]);
    expect(recorded).toEqual([]);
  });

  it('leaves a store the next open migrates cleanly', () => {
    // "Next open retries" is the whole recovery story for an interrupted
    // migration, and it is only true if the failed attempt left nothing behind
    // that the retry would now skip.
    const raw = store.openRaw();
    const filled = fillStore(raw);
    expect(
      errorFrom(() => {
        applyMigrations(raw, store.dbFile);
      }),
    ).toBeDefined();
    filled.restore();
    raw.close();

    expect(
      errorFrom(() => {
        store.open().close();
      }),
    ).toBeUndefined();
    const reader = store.openRaw();
    try {
      expect(integrityOf(reader)).toBe('ok');
    } finally {
      reader.close();
    }
  });
});
