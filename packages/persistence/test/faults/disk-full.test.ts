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
 * real repositories and the real shared envelopes over a raw handle — and, via
 * `UNSAFE_TEST_ONLY_RAW_HANDLE`, the facade's own connection, which is what
 * reaches the blanket fail-open closures in `database.ts`. Those closures are
 * the sites the store's fail-open policy is really made of: every one of them
 * turns a full disk, a locked file and a caller bug into the same discarded
 * `false`, so they are where "the write vanished and nothing said so" has to be
 * pinned as the actual behaviour.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type {
  AuditEventInput,
  ConfigScanRecord,
  InventoryContext,
  ProjectFilesScan,
} from '@akasecurity/schema';
import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { UNSAFE_TEST_ONLY_RAW_HANDLE } from '../../src/database.ts';
import { failOpenTransaction } from '../../src/internal/transactions.ts';
import { applyMigrations } from '../../src/migrations.ts';
import { SqliteAuditEventsRepository } from '../../src/repositories/audit-events.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { errorFrom } from '../helpers/errors.ts';
import type { FilledStore } from '../helpers/fault-injection.ts';
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

function countRows(db: DatabaseSync, table: string): number {
  return (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;
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

/**
 * The five blanket fail-open closures in `database.ts`, faulted on the
 * connection they actually write through.
 *
 * These are the class-blind sites: each wraps its work in `failOpenTransaction`
 * (or, for `reconcileWorktreeProjects`, a bare `catch {}`) and discards the
 * outcome, so a full disk arrives at the caller as exactly nothing. Every case
 * below documents that as the ACTUAL behaviour rather than the desirable one.
 * There is no dropped-write counter and no marker, so none is asserted — a test
 * demanding a signal the product does not emit would be a feature request in
 * assertion form. What IS asserted is the silence itself, on the one channel
 * that could plausibly change: nothing reaches stderr.
 *
 * They reach the closures through `UNSAFE_TEST_ONLY_RAW_HANDLE`. A second handle
 * on the same file carries none of the cap, which is why this needed a seam
 * rather than another `openRaw()`.
 */
describe('the facade’s fail-open closures with no room left', () => {
  /** Bound on the fill loop — a backstop, not the expected count. */
  const MAX_CAPTURES_TO_FILL = 128;
  /**
   * Bigger than the slack `fillToRefusal` can leave behind.
   *
   * That helper stops when a PAGE_HUNGRY capture is refused, which leaves up to
   * a page of room inside the pages the store already has — enough for a small
   * write to land. A closure whose payload is sized like this cannot fit in it
   * whatever the page size, so its refusal is a property rather than an
   * arithmetic coincidence that holds on one runner. `ensureInventory` proved
   * that the hard way: at 4 KiB it committed, and every assertion about a
   * dropped write passed against a write that had simply fit.
   */
  const OVERSIZE_CONTENT = 'x'.repeat(64 * 1024);

  function capture(db: LocalDatabase): void {
    const event = captureEvent({ content: PAGE_HUNGRY_CONTENT });
    db.recordCapture(event, [captureFinding(event.id)]);
  }

  /**
   * Run `fn` and report what it threw and what it said on stderr.
   *
   * "The caller is told nothing" is two claims, and only one of them is worth a
   * test. The return value is `void` in the signature, so asserting it comes
   * back `undefined` asserts TypeScript rather than the store. Stderr is the
   * half that could change: `akaWarn` is the package's one loud channel, it
   * already writes on three other paths, and none of these closures uses it —
   * so a warning added here goes red, and the silence stops being an accident
   * nobody wrote down.
   */
  function outcomeOf(fn: () => void): { err: Error | undefined; stderr: string[] } {
    const stderr: string[] = [];
    const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    try {
      return { err: errorFrom(fn), stderr };
    } finally {
      write.mockRestore();
    }
  }

  /**
   * Cap the facade's own connection, then spend the free space the store still
   * had, so the next write is refused rather than absorbed.
   *
   * The cap is on pages, not rows: a fresh store carries free space inside the
   * pages it already has, and the first captures land in it. Every case here
   * asserts that something did NOT happen, so a store still holding room would
   * satisfy all of them without refusing anything — which is why the refusal is
   * REACHED and then checked, never assumed.
   */
  function fillToRefusal(db: LocalDatabase): FilledStore {
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const filled = fillStore(raw, { headroomPages: 0 });
    let previous = -1;
    for (let i = 0; i < MAX_CAPTURES_TO_FILL && countAuditEvents(raw) !== previous; i += 1) {
      previous = countAuditEvents(raw);
      capture(db);
    }
    const before = countAuditEvents(raw);
    capture(db);
    expect(countAuditEvents(raw)).toBe(before);
    // And the fault is named, not inferred. The closures swallow the error, so
    // nothing downstream can say WHICH failure it was — without this the whole
    // block would rest on "a write did not land", which a dedup, a validation
    // reject or a silent no-op satisfies just as well as a full store.
    const probe = errorFrom(() => {
      new SqliteAuditEventsRepository(raw).insertAuditEvent(auditEvent());
    });
    expect(primaryCode(probe)).toBe(SQLITE_FULL);
    return filled;
  }

  it('recordCapture fails open and tells the caller nothing', () => {
    const db = store.open();
    const filled = fillToRefusal(db);

    const event = captureEvent({ content: PAGE_HUNGRY_CONTENT });
    const { err, stderr } = outcomeOf(() => {
      db.recordCapture(event, [captureFinding(event.id)]);
    });
    filled.restore();

    // Fail-open is the store's first principle: a throw here travels up into
    // the hook that called it, which is the one outcome the product forbids.
    expect(err).toBeUndefined();
    // And the drop is silent. Nothing is returned (the signature is `void`) and
    // nothing is said — so a full disk, a locked file and a caller bug are the
    // same non-event to everything downstream. Documented, not asserted away.
    expect(stderr).toEqual([]);
  });

  it('recordCapture leaves no partial rows — not the event, not its findings', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const filled = fillToRefusal(db);
    const events = countAuditEvents(raw);
    const findings = countRows(raw, 'inspection_findings');

    const event = captureEvent({ content: PAGE_HUNGRY_CONTENT });
    db.recordCapture(event, [captureFinding(event.id), captureFinding(event.id)]);
    filled.restore();

    // The claim that matters more than fail-open. An audit event whose findings
    // did not land, or findings pointing at an event that is not there, reads
    // as a healthy store on every surface while telling a lie.
    expect(countAuditEvents(raw)).toBe(events);
    expect(countRows(raw, 'inspection_findings')).toBe(findings);
  });

  it('recordCapture corrupts nothing and leaves no transaction open', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const filled = fillToRefusal(db);

    const event = captureEvent({ content: PAGE_HUNGRY_CONTENT });
    db.recordCapture(event, [captureFinding(event.id)]);

    expect(integrityOf(raw)).toBe('ok');
    // A transaction left behind by the fault is worse than the fault: the
    // connection keeps its locks and every later write on it silently joins a
    // transaction nobody started. This connection is the one the whole process
    // shares, so that would outlive the fault by the life of the handle.
    assertNoOpenTransaction(raw);

    filled.restore();

    // The positive control, and the criterion's "store still openable": the
    // refusals were the cap, not damage. Without it every assertion above holds
    // just as well on a store this fault had broken for good.
    capture(db);
    expect(countAuditEvents(raw)).toBeGreaterThan(0);
    expect(integrityOf(raw)).toBe('ok');
  });

  it('ensureInventory fails open to an empty resolution', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const filled = fillToRefusal(db);
    const inventory = countRows(raw, 'inventory');
    const projects = countRows(raw, 'source_project');

    const ctx: InventoryContext = {
      host: {
        objectType: 'host',
        identityKey: `machine-${randomUUID()}`,
        title: 'a-laptop',
        attributes: { padding: OVERSIZE_CONTENT },
      },
      project: { url: `https://example.invalid/${randomUUID()}.git`, name: 'repo', attributes: {} },
    };
    // `unset` rather than `undefined`, so "resolved to nothing" and "never ran"
    // stay distinguishable — a throw would leave the latter.
    let resolved: unknown = 'unset';
    const { err, stderr } = outcomeOf(() => {
      resolved = db.ensureInventory(ctx);
    });
    filled.restore();

    expect(err).toBeUndefined();
    expect(stderr).toEqual([]);
    // The one closure with a return value, and it says only "nothing resolved".
    // A caller cannot tell that apart from a context carrying no dimensions.
    expect(resolved).toEqual({});
    expect(countRows(raw, 'inventory')).toBe(inventory);
    expect(countRows(raw, 'source_project')).toBe(projects);
    assertNoOpenTransaction(raw);
  });

  it('recordConfigScan fails open and writes no part of the scan', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const filled = fillToRefusal(db);
    const events = countAuditEvents(raw);
    const inventory = countRows(raw, 'inventory');

    const record: ConfigScanRecord = {
      items: [
        {
          objectType: 'skill',
          identityKey: `skill-${randomUUID()}`,
          title: 'a-skill',
          attributes: { padding: OVERSIZE_CONTENT },
        },
      ],
      scanEvent: {
        id: randomUUID(),
        eventType: 'config_scan',
        startedAt: new Date().toISOString(),
        content: OVERSIZE_CONTENT,
      },
    };
    const { err, stderr } = outcomeOf(() => {
      db.recordConfigScan(record);
    });
    filled.restore();

    expect(err).toBeUndefined();
    expect(stderr).toEqual([]);
    // One transaction covers the inventory upserts AND the scan event, so a
    // torn scan is the failure to rule out: inventory rows recorded as seen by
    // a scan whose own event never landed.
    expect(countAuditEvents(raw)).toBe(events);
    expect(countRows(raw, 'inventory')).toBe(inventory);
    assertNoOpenTransaction(raw);
  });

  it('recordProjectFiles fails open and leaves the stored tree untouched', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    // Seeded before the cap: the interesting claim is that a failed scan does
    // not PRUNE, and an empty tree could not show that.
    const projectId = db.sourceProject.upsert(
      { url: `https://example.invalid/${randomUUID()}.git`, name: 'repo', attributes: {} },
      Date.now(),
    );
    db.recordProjectFiles(projectId, {
      files: [{ path: 'src/app.ts', name: 'app.ts', origin: 'source', defaultAccess: 'approved' }],
      truncated: false,
      scannedAt: new Date().toISOString(),
    });
    const seeded = countRows(raw, 'project_file');
    expect(seeded).toBe(1);

    const filled = fillToRefusal(db);
    // Padded names, for the same reason as OVERSIZE_CONTENT: 64 short paths are
    // a few kilobytes and could land in the slack the fill leaves.
    const scan: ProjectFilesScan = {
      files: Array.from({ length: 256 }, (_, i) => {
        const name = `${'f'.repeat(200)}${String(i)}.ts`;
        return {
          path: `src/generated/${name}`,
          name,
          origin: 'source' as const,
          defaultAccess: 'approved' as const,
        };
      }),
      truncated: false,
      scannedAt: new Date().toISOString(),
    };
    const { err, stderr } = outcomeOf(() => {
      db.recordProjectFiles(projectId, scan);
    });
    filled.restore();

    expect(err).toBeUndefined();
    expect(stderr).toEqual([]);
    // The whole replace-and-prune pass rolls back together: the new files are
    // absent AND the pre-existing row survives. Pruning without inserting would
    // be the torn outcome here, and it would look like an empty project.
    expect(countRows(raw, 'project_file')).toBe(seeded);
  });

  it('reconcileWorktreeProjects fails open on a store with no room', () => {
    const db = store.open();
    const raw = db[UNSAFE_TEST_ONLY_RAW_HANDLE];
    const headRoot = '/repos/payments';
    const canonicalId = db.sourceProject.upsert(
      { url: 'https://example.invalid/payments.git', name: 'payments', attributes: {} },
      Date.now(),
    );
    const worktreeRoot = `${headRoot}/.claude/worktrees/wt-${randomUUID()}`;
    db.sourceProject.upsert({ url: worktreeRoot, name: 'payments', attributes: {} }, Date.now());

    const filled = fillToRefusal(db);
    const { err, stderr } = outcomeOf(() => {
      db.reconcileWorktreeProjects(canonicalId, headRoot, worktreeRoot);
    });
    filled.restore();

    // Only the fail-open claim, deliberately. This closure DELETES rows, so
    // whether a capped store refuses it depends on whether the rollback journal
    // needs a page it cannot get — the row count is not a property that holds
    // either way, and asserting one would pin the page arithmetic instead of
    // the behaviour.
    expect(err).toBeUndefined();
    // Its fail-open is a bare `catch {}` rather than `failOpenTransaction`, and
    // it is the one site here that sits next to a real `akaWarn` caller
    // (the source-project reconcile failure) — so the silence is worth pinning.
    expect(stderr).toEqual([]);
    assertNoOpenTransaction(raw);
    expect(integrityOf(raw)).toBe('ok');
  });
});
