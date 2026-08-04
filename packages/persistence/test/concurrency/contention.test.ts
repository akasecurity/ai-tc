/**
 * Two live write handles on one store — the shape the product actually runs in.
 *
 * Plugin hooks, the CLI and the dashboard each open their own `LocalDatabase`
 * on the same `aka.db` with nothing between them. WAL and
 * `PRAGMA busy_timeout = 2000` are the entire mitigation: there is no retry, no
 * backoff, no advisory lock and no write queue anywhere in the package.
 *
 * Two structural facts shape every test below.
 *
 * **node:sqlite is synchronous**, so two handles on one thread interleave
 * rather than collide. Interleaving is worth pinning on its own — it is what
 * proves the write paths coexist and stay mutually visible — but it is not
 * contention. Real contention needs the write lock held from somewhere this
 * thread is not, which is what `lockStore` does on a worker.
 *
 * **`recordCapture` returns `void`.** It wraps its work in
 * `failOpenTransaction`, which swallows every error and returns a boolean the
 * caller discards, so a dropped write is indistinguishable from a successful
 * one at the call site. The only way to account for an event is to count rows
 * afterwards — which is why these tests read the store back through a raw
 * handle instead of asserting on a return value.
 *
 * Nothing here asserts an elapsed time. Contention outcomes are pinned as
 * result codes and row counts, both of which are the same on a fast laptop and
 * a loaded Windows runner.
 */
import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { DetectedFindingWithKey, IngestEvent } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';
import { captureId } from '../../src/ids.ts';
import { applyMigrations } from '../../src/migrations.ts';
import { lockStore, primaryCode, SQLITE_BUSY } from '../helpers/fault-injection.ts';
import { withTempStore } from '../helpers/temp-store.ts';
import { assertNoOpenTransaction } from '../helpers/transactions.ts';
import { withTwoWriters, withWriters } from '../helpers/with-two-writers.ts';

// A capture's audit row is content-addressed on (sessionId, contentHash,
// filePath), so a distinct contentHash per event is what keeps N writes N rows
// rather than one deduplicated row.
function event(contentHash: string, overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash,
    content: 'here is a key <redacted>',
    ...overrides,
  };
}

/**
 * Findings are deduplicated per session on (ruleId, maskedMatch, sessionId), so
 * one value crossing several surfaces in one action is recorded once. A fixture
 * reusing a single `maskedMatch` therefore collapses N findings to one and
 * makes a loss assertion read as a dedup. `distinct` keeps each finding a
 * different value; the tests that want the dedup pass the same one on purpose.
 *
 * Deliberately not `overrides`-shaped like `event` above: overriding `ruleId` or
 * `maskedMatch` from a call site is exactly what re-arms that dedup, so the one
 * field a caller may vary is the one that keeps findings distinct.
 */
function finding(distinct: string = randomUUID()): DetectedFindingWithKey {
  return {
    id: randomUUID(),
    eventId: randomUUID(),
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 14, end: 34 },
    maskedMatch: `AKIA…${distinct}`,
    actionTaken: 'block',
    confidence: 0.9,
  };
}

// `ensureSessionRoot` plants an event_type = 'session' row per session before
// the capture's own row FKs onto it, so counting captures means excluding those
// structural roots rather than counting the table. Stated as "not a root" rather
// than "is a prompt": pinning the fixture's own `kind` default here would make a
// test that captures some other kind read as loss.
function captureCount(db: DatabaseSync): number {
  return (
    db.prepare("SELECT count(*) AS n FROM audit_events WHERE event_type != 'session'").get() as {
      n: number;
    }
  ).n;
}

function hasCapture(db: DatabaseSync, contentHash: string): boolean {
  const row = db
    .prepare('SELECT count(*) AS n FROM audit_events WHERE content_hash = ?')
    .get(contentHash) as { n: number };
  return row.n > 0;
}

function findingCount(db: DatabaseSync): number {
  return (db.prepare('SELECT count(*) AS n FROM inspection_findings').get() as { n: number }).n;
}

/**
 * The store's own verdict on its pages. A concurrency test that only counted
 * rows would miss a half-written b-tree, which is the failure mode WAL exists
 * to prevent and therefore the one worth asking about directly.
 *
 * The `| undefined` is not decorative: `get()` returns undefined for no row, so
 * without it the optional read below would throw a TypeError rather than report
 * the missing verdict it exists to report.
 */
function integrity(db: DatabaseSync): string {
  const row = db.prepare('PRAGMA integrity_check').get() as
    { integrity_check?: string } | undefined;
  return row?.integrity_check ?? 'missing';
}

function ledgerTags(db: DatabaseSync): string[] {
  return (
    db.prepare('SELECT tag FROM migration_ledger ORDER BY tag').all() as { tag: string }[]
  ).map((row) => row.tag);
}

describe('two live write handles', () => {
  it('interleaved recordCapture from two handles loses nothing and corrupts nothing', () => {
    withTwoWriters((a, b, store) => {
      // Alternating, not two blocks: each write lands on top of a WAL frame the
      // other connection committed, which is the ordering a block-at-a-time
      // loop never produces.
      const hashes: string[] = [];
      for (let i = 0; i < 10; i += 1) {
        const writer = i % 2 === 0 ? a : b;
        const hash = `interleaved-${String(i)}`;
        hashes.push(hash);
        writer.recordCapture(event(hash, { metadata: { sessionId: `s-${String(i % 2)}` } }), [
          finding(hash),
        ]);
      }

      const raw = store.openRaw();
      expect(captureCount(raw)).toBe(hashes.length);
      for (const hash of hashes) {
        expect(hasCapture(raw, hash)).toBe(true);
      }
      // One finding per capture: a lost or doubled child row is a corruption a
      // parent-row count alone cannot see.
      expect(findingCount(raw)).toBe(hashes.length);
      expect(integrity(raw)).toBe('ok');
    });
  });

  it("each handle reads the other's committed writes", () => {
    withTwoWriters((a, b) => {
      a.recordCapture(event('written-by-a'), [finding()]);
      b.recordCapture(event('written-by-b'), [finding()]);

      // Read back through each handle in turn, not through a raw connection: a
      // handle that could not see its peer's row would still pass a raw-handle
      // check, since that is a third connection with its own snapshot.
      const idFromA = captureId(null, 'written-by-a', null);
      const idFromB = captureId(null, 'written-by-b', null);

      expect(a.auditEvents.findById(idFromA)).toBeDefined();
      expect(b.auditEvents.findById(idFromB)).toBeDefined();
      // The crossing pair — each handle reading what the other committed.
      expect(a.auditEvents.findById(idFromB)).toBeDefined();
      expect(b.auditEvents.findById(idFromA)).toBeDefined();
    });
  });

  it('the same capture written by both handles collapses to one row', () => {
    withTwoWriters((a, b, store) => {
      // Two processes scanning the same content in one session is ordinary — a
      // hook and a reconcile pass over the same transcript tail. The audit id is
      // content-addressed and inserted OR IGNORE, so the second write is a no-op
      // rather than a duplicate or a constraint failure. The one `maskedMatch`
      // across both writes is deliberate for the same reason: the same value in
      // the same session is what the finding-level dedup exists for.
      const same = event('identical-content', { metadata: { sessionId: 's-shared' } });
      a.recordCapture(same, [finding('shared-value')]);
      b.recordCapture(same, [finding('shared-value')]);

      const raw = store.openRaw();
      expect(captureCount(raw)).toBe(1);
      expect(findingCount(raw)).toBe(1);
      expect(integrity(raw)).toBe('ok');
    });
  });
});

describe('many writers on one store', () => {
  const WRITERS = 5;
  /**
   * Every `recordCapture` is its own transaction, and a WAL commit fsyncs at
   * SQLite's default `synchronous = FULL`. That costs well under a millisecond
   * on a developer machine and around 40ms on the Windows CI runner, so the same
   * 500 writes are ~90ms in one place and ~20s in the other.
   *
   * Volume is therefore cut where the writes are expensive. It is cut rather
   * than skipped, and cut on the axis that only buys throughput: the property —
   * N live writers on one store, every event accounted for — is asserted
   * identically on both, and the writer count, which is the concurrency being
   * tested, does not move.
   *
   * The reason to bound it at all rather than raise the timeout: this body is
   * synchronous, so vitest cannot interrupt it. A test over its budget does not
   * fail at the limit — it runs to completion and reports afterwards, so on a
   * slow enough runner the job's own budget is what gives out instead.
   */
  const EVENTS_PER_WRITER = process.platform === 'win32' ? 20 : 100;

  it("every writer's events all land, and the store stays consistent", () => {
    withWriters(WRITERS, (writers, store) => {
      const attempted = WRITERS * EVENTS_PER_WRITER;
      for (let i = 0; i < EVENTS_PER_WRITER; i += 1) {
        // Round-robin across handles rather than draining one at a time, so the
        // store sees writes from five connections interleaved throughout.
        for (const [index, writer] of writers.entries()) {
          const hash = `w${String(index)}-e${String(i)}`;
          writer.recordCapture(
            event(hash, { metadata: { sessionId: `session-${String(index)}` } }),
            [finding(hash)],
          );
        }
      }

      const raw = store.openRaw();
      const landed = captureCount(raw);
      // `recordCapture` reports nothing, so accounting is this subtraction and
      // nothing else. Naming the shortfall is the point: comparing the counts
      // says a number was wrong, this says how many events the store lost.
      expect(attempted - landed).toBe(0);
      expect(findingCount(raw)).toBe(attempted);
      // Every session root is present too — the roots are written inside the
      // same transaction as their captures, so a torn pass would show up here.
      const roots = (
        raw
          .prepare("SELECT count(*) AS n FROM audit_events WHERE event_type = 'session'")
          .get() as {
          n: number;
        }
      ).n;
      expect(roots).toBe(WRITERS);
      expect(integrity(raw)).toBe('ok');
    });
  });
});

describe('a writer holding the write lock past busy_timeout', () => {
  it("drops the other writer's capture silently — no throw, no row, no signal", () => {
    // One writer, not two: the contention comes from the lock holder on its own
    // thread, so a second handle here would only pay for a migration pass.
    withTempStore((store) => {
      const a = store.open();
      // Positive control first. Without it, "no row landed" is satisfied by an
      // event the store would have rejected anyway, and the test would pass
      // against a `recordCapture` that never writes at all.
      a.recordCapture(event('uncontended'), [finding()]);
      // One raw handle for the whole test: each statement on it runs in
      // autocommit and so sees the latest committed state, before the lock and
      // after it alike.
      const raw = store.openRaw();
      expect(hasCapture(raw, 'uncontended')).toBe(true);

      // Held with no `holdMs`, so it outlasts the victim's whole 2000 ms
      // `busy_timeout` however slow the machine is — the wait is bounded by the
      // victim's timeout, not by a duration this test has to guess.
      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

      let threw: unknown;
      try {
        a.recordCapture(event('contended'), [finding()]);
      } catch (err) {
        threw = err;
      }
      lock.release();

      // The documented behaviour, asserted rather than assumed: the capture
      // path swallows SQLITE_BUSY whole. The caller is told nothing, and the
      // event is gone. This is the fail-open policy working as designed — a
      // dropped event must never break the host session — and the cost of it.
      expect(threw).toBeUndefined();
      expect(hasCapture(raw, 'contended')).toBe(false);
      // Only the control survived, so the drop cost exactly the one event.
      expect(captureCount(raw)).toBe(1);
      expect(integrity(raw)).toBe('ok');
    });
  });

  it('leaves the losing handle usable once the lock is gone', () => {
    withTempStore((store) => {
      const a = store.open();
      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
      a.recordCapture(event('dropped'), [finding()]);
      lock.release();

      a.recordCapture(event('after-release'), [finding()]);

      // A rolled-back transaction left open on `a` would not fail this write —
      // `failOpenTransaction` would nest it in a SAVEPOINT and RELEASE it into
      // the open transaction, where it stays invisible to every other
      // connection until a COMMIT that never comes. Reading the row back from a
      // separate handle is therefore what proves the failure was contained.
      const raw = store.openRaw();
      expect(hasCapture(raw, 'after-release')).toBe(true);
      expect(hasCapture(raw, 'dropped')).toBe(false);
      expect(integrity(raw)).toBe('ok');
    });
  });

  it('waits and succeeds when the lock is released inside busy_timeout', () => {
    withTempStore((store) => {
      const a = store.open();
      // The counterpart to the drop above: brief contention is absorbed, so
      // "the write is dropped" is a statement about exhausting the timeout, not
      // about contention as such. 200 ms against a 2000 ms timeout is a 10x
      // margin deliberately kept clear of the boundary — do not tune it closer.
      const lock = lockStore(store.dbFile, { holdMs: 200, onCleanup: store.onCleanup });
      a.recordCapture(event('waited'), [finding()]);
      lock.release();

      const raw = store.openRaw();
      expect(hasCapture(raw, 'waited')).toBe(true);
      expect(integrity(raw)).toBe('ok');
    });
  });

  it('refuses to open a second handle, loudly, while the lock is held', () => {
    withTempStore((store) => {
      // Take a handle before the lock: `openLocalDatabase` writes on the way in
      // (journal_mode, the migration pass, the ensure* passes), so opening
      // under a held lock is a contended write rather than a read.
      store.open();
      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });

      const err = (() => {
        try {
          openLocalDatabase(store.dataDir);
          return undefined;
        } catch (caught) {
          return caught;
        }
      })();
      lock.release();

      // The one contention path in the package that is not silent. A hook
      // starting while another process holds the write lock past 2 s does not
      // open the store at all — it throws, and the caller takes its
      // store-unavailable path instead of scanning against a handle it does not
      // have. Asserted as a result code, not a message: `errcode` carries the
      // extended code and the refinement is not the point here.
      expect(err).toBeDefined();
      expect(primaryCode(err)).toBe(SQLITE_BUSY);
    });
  });
});

describe('concurrent applyMigrations', () => {
  it('a second handle on a fresh store adopts the first migration pass', () => {
    withTempStore((store) => {
      const a = store.open();
      const raw = store.openRaw();
      const afterFirst = ledgerTags(raw);
      // A non-empty ledger is the positive control: an empty one converges with
      // every other empty one, and every assertion below would hold vacuously.
      expect(afterFirst.length).toBeGreaterThan(0);
      expect(new Set(afterFirst).size).toBe(afterFirst.length);

      const b = store.open();
      const afterSecond = ledgerTags(raw);

      // Convergence, asserted as set equality across passes rather than against
      // a migration count — a new migration moves the count and must not move
      // this test.
      expect(afterSecond).toStrictEqual(afterFirst);
      expect(new Set(afterSecond).size).toBe(afterSecond.length);

      // Both handles are live afterwards, which a ledger comparison alone does
      // not show: an adopter that reached the right ledger state through a
      // half-applied schema would still fail here.
      a.recordCapture(event('by-first-opener'), [finding()]);
      b.recordCapture(event('by-second-opener'), [finding()]);
      expect(captureCount(raw)).toBe(2);
      expect(integrity(raw)).toBe('ok');
    });
  });

  it('replaying applyMigrations on a migrated store writes no duplicate tags', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      const before = ledgerTags(raw);
      expect(before.length).toBeGreaterThan(0);

      // What every re-open of the store already does, reduced to the one call
      // that matters.
      //
      // What this reaches, and what it does not: the applier reads the ledger
      // into an `applied` set up front and skips any tag already in it, so a
      // replay converges by never reaching the insert. The `OR IGNORE` on that
      // insert guards a different case — two processes that both read the
      // ledger before either has written it, and so both try to record the same
      // tag. That set is read and written inside one synchronous call, so no
      // single-threaded test can open a window between the two; reaching it
      // needs a second process racing this one.
      applyMigrations(raw, store.dbFile);
      applyMigrations(raw, store.dbFile);

      const after = ledgerTags(raw);
      expect(after).toStrictEqual(before);
      expect(new Set(after).size).toBe(after.length);
      expect(integrity(raw)).toBe('ok');
      // `applyMigrations` runs its work inside a BEGIN IMMEDIATE, and a rollback
      // that itself failed would leave that transaction open on this handle.
      // Nothing above can see that: SELECT and PRAGMA integrity_check both
      // answer normally from inside an open transaction, so every assertion in
      // this test passes while the handle silently holds the write lock.
      assertNoOpenTransaction(raw);
    });
  });

  it('user_version converges with the ledger', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      const version = (): number =>
        (raw.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;

      // The property a second opener must not disturb: the counter is written
      // once, on the pass that finds it behind, and a later open leaves it
      // alone.
      const before = version();
      expect(before).toBeGreaterThan(0);
      store.open();
      expect(version()).toBe(before);

      // Deliberately not asserted as an invariant of the applier: `user_version`
      // is set from the migration count, never derived from the ledger, so the
      // two agree here only because a fresh store applies every migration. A
      // migration that defers on a fresh store — the applier already has one
      // conditional tag — would part them without either being wrong.
      expect(ledgerTags(raw).length).toBeLessThanOrEqual(before);
    });
  });
});

describe('a WAL reader during writes', () => {
  it('sees a consistent snapshot for the life of its read transaction', () => {
    withTempStore((store) => {
      const a = store.open();
      a.recordCapture(event('before-reader'), [finding()]);

      const reader = store.openRaw();
      expect(
        (reader.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode,
      ).toBe('wal');

      // A DEFERRED transaction takes its snapshot at the first read, not at
      // BEGIN, so the count below is what fixes the snapshot in place.
      reader.exec('BEGIN');
      const before = captureCount(reader);
      expect(before).toBe(1);

      // Committed by another connection while the read transaction is open.
      a.recordCapture(event('during-read'), [finding()]);
      expect(captureCount(reader)).toBe(before);
      expect(hasCapture(reader, 'during-read')).toBe(false);

      reader.exec('COMMIT');

      // The positive control for the two assertions above: without it, a write
      // that never landed would satisfy them both. The reader was holding a
      // snapshot, not looking at an empty store.
      expect(captureCount(reader)).toBe(before + 1);
      expect(hasCapture(reader, 'during-read')).toBe(true);
      expect(integrity(reader)).toBe('ok');
    });
  });

  it('does not block the writer it is reading past', () => {
    withTempStore((store) => {
      const a = store.open();
      const reader = store.openRaw();
      reader.exec('BEGIN');
      // Discarded on purpose: a DEFERRED transaction takes its snapshot at the
      // first read, so this call is what puts the reader on one. Deleting it
      // leaves the test green and testing nothing.
      captureCount(reader);

      // WAL's one-writer-N-readers property, stated as an outcome: the open
      // read transaction neither delays nor drops the write. A reader that took
      // a shared lock the writer had to wait out would surface here as a
      // dropped capture, exactly as the held write lock does above.
      a.recordCapture(event('written-past-reader'), [finding()]);
      reader.exec('COMMIT');

      expect(hasCapture(reader, 'written-past-reader')).toBe(true);
      expect(integrity(reader)).toBe('ok');
    });
  });
});
