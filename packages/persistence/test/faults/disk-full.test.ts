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
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { AuditEventInput } from '@akasecurity/schema';
import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
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
  it('raises SQLITE_FULL and leaves no partial rows behind', () => {
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
  /**
   * Cap a fresh store so the applier commits some migrations and then runs out,
   * leaving a genuinely half-migrated file.
   *
   * The cap is measured, not guessed. `fillStore`'s default headroom on an
   * empty file caps at 2 pages, which the ledger's own `CREATE TABLE` exhausts
   * — the applier's loop never runs at all, and every assertion about a partial
   * migration then holds on a store with no tables in it. Half of what a
   * complete migration actually needs lands partway instead, and it keeps
   * doing so as the migration history grows.
   */
  function halfMigratedStore(): { db: DatabaseSync; file: string; err: Error | undefined } {
    const seeded = store.open();
    seeded.close();
    const measured = store.openRaw();
    const fullPages = (measured.prepare('PRAGMA page_count').get() as { page_count: number })
      .page_count;
    measured.close();

    const file = join(store.dataDir, 'half-migrated.db');
    const db = new DatabaseSync(file);
    const filled = fillStore(db, { headroomPages: Math.floor(fullPages / 2) });
    const err = errorFrom(() => {
      applyMigrations(db, file);
    });
    filled.restore();
    return { db, file, err };
  }

  function ledgerTags(db: DatabaseSync): string[] {
    const present = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'migration_ledger'")
      .all() as { name: string }[];
    if (present.length === 0) return [];
    return (db.prepare('SELECT tag FROM migration_ledger').all() as { tag: string }[]).map(
      (row) => row.tag,
    );
  }

  it('records a ledger tag only for a migration that actually landed', () => {
    // The applier stamps a ledger tag per migration. A tag recorded for DDL
    // that did not land is the worst outcome available here: every later open
    // reads the tag, skips the migration, and meets a schema that was never
    // built. The tag must therefore go in with the DDL, inside one transaction.
    const { db, err } = halfMigratedStore();
    try {
      expect(primaryCode(err)).toBe(SQLITE_FULL);
      assertNoOpenTransaction(db);

      const recorded = ledgerTags(db);
      // Positive control. With no tags recorded — which is what a 2-page cap
      // produces — every claim below holds vacuously on an empty file, and the
      // defect this case exists for is undetectable.
      expect(recorded.length).toBeGreaterThan(0);
      expect(recorded.length).toBeLessThan(SQLITE_MIGRATIONS.length);

      // What is recorded is an unbroken prefix of the history, never a tag
      // from beyond the point the disk gave out.
      const expected = SQLITE_MIGRATIONS.slice(0, recorded.length).map((m) => m.tag);
      expect([...recorded].sort()).toEqual([...expected].sort());
    } finally {
      db.close();
    }
  });

  it('leaves a half-migrated store the next open finishes', () => {
    // "Next open retries" is the whole recovery story for an interrupted
    // migration, and it is only true of a store that really is partway: a tag
    // recorded without its DDL makes the retry SKIP that migration, so the
    // schema it should have built never appears and the open fails on it.
    const { db, file } = halfMigratedStore();
    const before = ledgerTags(db).length;
    db.close();
    expect(before).toBeGreaterThan(0);
    expect(before).toBeLessThan(SQLITE_MIGRATIONS.length);

    const reopened = new DatabaseSync(file);
    try {
      expect(
        errorFrom(() => {
          applyMigrations(reopened, file);
        }),
      ).toBeUndefined();
      expect(ledgerTags(reopened)).toHaveLength(SQLITE_MIGRATIONS.length);
      expect(integrityOf(reopened)).toBe('ok');
    } finally {
      reopened.close();
    }
  });
});
