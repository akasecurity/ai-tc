// A store written by a NEWER build than the one opening it.
//
// The applier skips when the store's history is ahead (there is nothing of its
// own left to apply), and the repository constructors then prepare against a
// schema this build does not know. That throws a bare SQLite error — the one
// measured in the field was `cannot UPSERT a view`, from a build predating the
// migration that turned `findings` into a legacy compat view — which every
// caller above collapses into "the store could not be opened". The store is
// intact; what is stale is the binary. These cases pin the difference.
import type { DatabaseSync } from 'node:sqlite';

import { SQLITE_MIGRATIONS } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../src/database.ts';
import {
  describeStoreSkew,
  isSchemaShapedFailure,
  StoreAheadOfBuildError,
} from '../src/store-skew.ts';
import { errorFrom } from './helpers/errors.ts';
import {
  corruptStore,
  lockStore,
  primaryCode,
  readOnlyStore,
  SQLITE_BUSY,
  SQLITE_CONSTRAINT,
  SQLITE_CORRUPT,
  SQLITE_FULL,
  SQLITE_NOTADB,
  SQLITE_READONLY,
  SQLITE_READONLY_DIRECTORY,
} from './helpers/fault-injection.ts';
import { withTempStore } from './helpers/temp-store.ts';

// Lexically past every real tag, so it sorts last and can never collide with one
// a future migration adds.
const FUTURE_TAG = '9999_from_a_newer_build';

// Codes the fault-injection helpers do not name, each because no fixture
// produces it on demand. SQLITE_ERROR is what the engine answers when a
// statement stops matching the schema (`cannot UPSERT a view`) — a shape, not a
// fault a test can inject. The other two are the EXTENDED forms of the helper's
// primary codes, and they are what pins the low-byte arithmetic from the accept
// side and the refuse side at once.
const SQLITE_ERROR = 1;
const SQLITE_CONSTRAINT_NOTNULL = 1299; // SQLITE_CONSTRAINT | (5 << 8)
const SQLITE_BUSY_SNAPSHOT = 517; // SQLITE_BUSY | (2 << 8)

/** Mark a store as carrying history this build does not define. */
function markWrittenByNewerBuild(db: DatabaseSync, tag = FUTURE_TAG): void {
  db.prepare('INSERT OR IGNORE INTO migration_ledger (tag, applied_at) VALUES (?, ?)').run(
    tag,
    Date.now(),
  );
  db.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length + 1)}`);
}

/**
 * Turn a real table into a view, the way `0014_drop_legacy_events_findings`
 * turned `events`/`findings` into compat views. `classified_data` is the target
 * because `SqliteClassifiedDataRepository` prepares an INSERT against it in its
 * CONSTRUCTOR, so the failure lands where the field failure landed — while
 * `openLocalDatabase` is still wiring repositories, before any caller can run a
 * statement of its own.
 */
function replaceTableWithView(db: DatabaseSync, table: string): void {
  db.exec(`ALTER TABLE ${table} RENAME TO ${table}_backing`);
  db.exec(`CREATE VIEW ${table} AS SELECT * FROM ${table}_backing`);
}

describe('isSchemaShapedFailure', () => {
  // The gate on the re-description, pinned as a table because the codes on both
  // sides are mostly unreachable from a fixture: nothing injects SQLITE_ERROR
  // (it is what a statement answers when the schema moved, not a fault), and
  // the environmental codes this must refuse are read by the store's own
  // helpers rather than produced here. The real faults below prove the open
  // path; this proves the predicate's arithmetic, extended codes included.
  it.each([
    ['SQLITE_ERROR, the shape of `cannot UPSERT a view`', SQLITE_ERROR],
    ['SQLITE_CONSTRAINT, a newer NOT NULL column', SQLITE_CONSTRAINT],
    ['SQLITE_CONSTRAINT_NOTNULL, the same refusal extended', SQLITE_CONSTRAINT_NOTNULL],
  ])('accepts %s', (_name, code) => {
    expect(isSchemaShapedFailure(Object.assign(new Error('schema'), { errcode: code }))).toBe(true);
  });

  // The codes that name the store or its host rather than its schema. An ahead
  // store can produce every one of them, so re-describing any would tell the
  // user their intact store is the problem and bury the code they need.
  it.each([
    ['SQLITE_BUSY', SQLITE_BUSY],
    ['SQLITE_BUSY_SNAPSHOT, the same contention extended', SQLITE_BUSY_SNAPSHOT],
    ['SQLITE_READONLY', SQLITE_READONLY],
    ['SQLITE_READONLY_DIRECTORY, a chmod\u2019d directory', SQLITE_READONLY_DIRECTORY],
    ['SQLITE_CORRUPT', SQLITE_CORRUPT],
    ['SQLITE_FULL', SQLITE_FULL],
    ['SQLITE_NOTADB', SQLITE_NOTADB],
  ])('refuses %s', (_name, code) => {
    expect(isSchemaShapedFailure(Object.assign(new Error('store'), { errcode: code }))).toBe(false);
  });

  it('refuses anything carrying no SQLite code at all', () => {
    // A repository constructor throwing a TypeError is a real possibility on
    // this path, and it is not the schema answering: only a code this build can
    // read is allowed to re-describe the store.
    expect(isSchemaShapedFailure(new TypeError('cannot read properties of undefined'))).toBe(false);
    expect(isSchemaShapedFailure('no such column')).toBe(false);
    expect(isSchemaShapedFailure(null)).toBe(false);
  });
});

describe('describeStoreSkew', () => {
  it('reports no skew for a store this build just created', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();

      expect(describeStoreSkew(raw)).toBeNull();
    });
  });

  it('names the ledger tags this build does not define', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      markWrittenByNewerBuild(raw);

      const skew = describeStoreSkew(raw);

      expect(skew).not.toBeNull();
      expect(skew?.unknownTags).toEqual([FUTURE_TAG]);
      expect(skew?.buildVersion).toBe(SQLITE_MIGRATIONS.length);
      expect(skew?.storeVersion).toBe(SQLITE_MIGRATIONS.length + 1);
    });
  });

  // A store whose ledger this build fully knows is NOT ahead, however the
  // count reads: `user_version` is stamped write-only so a downgrade stays a
  // no-op, and treating a stale count alone as skew would report every such
  // store as written by a newer build.
  it('does not call a store ahead on a bare version count it knows every tag of', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      raw.exec(`PRAGMA user_version = ${String(SQLITE_MIGRATIONS.length + 5)}`);

      expect(describeStoreSkew(raw)).toBeNull();
    });
  });
});

describe('openLocalDatabase on a store written by a newer build', () => {
  // The negative control, and the reason skew alone must not be a refusal: a
  // newer store is usually backward-compatible (added tables, columns and
  // indexes this build simply never reads). Those sessions work today and have
  // to keep working.
  it('opens a newer store whose schema this build can still use', () => {
    withTempStore((store) => {
      store.open().close();
      const raw = store.openRaw();
      raw.exec('CREATE TABLE something_a_newer_build_added (id TEXT PRIMARY KEY)');
      markWrittenByNewerBuild(raw);
      raw.close();

      const err = errorFrom(() => {
        openLocalDatabase(store.dataDir).close();
      });

      expect(err).toBeUndefined();
    });
  });

  it('reports the skew rather than the raw SQLite failure', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      replaceTableWithView(raw, 'classified_data');
      markWrittenByNewerBuild(raw);
      raw.close();

      const err = errorFrom(() => {
        openLocalDatabase(store.dataDir).close();
      });

      expect(err).toBeInstanceOf(StoreAheadOfBuildError);
      const skewErr = err as StoreAheadOfBuildError;
      expect(skewErr.unknownTags).toEqual([FUTURE_TAG]);
      expect(skewErr.storeVersion).toBe(SQLITE_MIGRATIONS.length + 1);
      expect(skewErr.buildVersion).toBe(SQLITE_MIGRATIONS.length);
      // The SQLite failure is what has to be preserved for a maintainer, and
      // the whole point of the wrapper is that nobody above has to read it.
      expect(skewErr.cause).toBeInstanceOf(Error);
      // ... and it is re-described for THIS code and no other: the failure has
      // to be one the schema explains, which is what the gate above reads.
      expect(primaryCode(skewErr.cause)).toBe(SQLITE_ERROR);
    });
  });

  // The other half of the gate, and the case that can go red on it: the failure
  // need not be CAUSED by the skew. This store is the negative control above —
  // ahead, but with a schema this build uses fine — and its real problem is the
  // file's permissions. Re-describing that as "the store is intact, update AKA"
  // would be false, would bury SQLITE_READONLY in `cause`, and would be the
  // advice every hook on a CLI-ahead-of-plugin machine gives for a chmod'd file.
  it('reports a read-only store as read-only even when the store is ahead', (ctx) => {
    withTempStore((store) => {
      store.open().close();
      const raw = store.openRaw();
      markWrittenByNewerBuild(raw);
      raw.close();
      const readOnly = readOnlyStore(store.dbFile, { onCleanup: store.onCleanup });
      if (!readOnly.effective) {
        ctx.skip('the mode change does not deny writes here (Windows, or running as root)');
        return;
      }

      const err = errorFrom(() => {
        openLocalDatabase(store.dataDir).close();
      });

      expect(err).not.toBeInstanceOf(StoreAheadOfBuildError);
      expect(primaryCode(err)).toBe(SQLITE_READONLY);
    });
  });

  // The contended sibling. This one costs the full `busy_timeout` (2 s) because
  // the open writes on its way in, which is also why the case is here at all:
  // a lock lost to another process is ordinary on a machine running three
  // surfaces, and none of them should be told to update AKA about it.
  it('reports a contended store as contention even when the store is ahead', () => {
    withTempStore((store) => {
      store.open().close();
      const raw = store.openRaw();
      markWrittenByNewerBuild(raw);
      raw.close();
      const lock = lockStore(store.dbFile, { onCleanup: store.onCleanup });
      try {
        const err = errorFrom(() => {
          openLocalDatabase(store.dataDir).close();
        });

        expect(err).not.toBeInstanceOf(StoreAheadOfBuildError);
        expect(primaryCode(err)).toBe(SQLITE_BUSY);
      } finally {
        lock.release();
      }
    });
  });

  it('says the store needs no repair, and never to move it aside', () => {
    withTempStore((store) => {
      store.open();
      const raw = store.openRaw();
      replaceTableWithView(raw, 'classified_data');
      markWrittenByNewerBuild(raw);
      raw.close();

      const err = errorFrom(() => {
        openLocalDatabase(store.dataDir).close();
      });

      expect(err?.message).toContain(FUTURE_TAG);
      // The remedy is updating the binary. Advice to move the store aside is
      // data loss here — the corpus is intact and a newer build reads it fine.
      expect(err?.message).not.toMatch(/aside|recreate|corrupt|permission/i);
    });
  });

  // The wrapper must not swallow every open failure into "you are out of date".
  // A store that is genuinely unreadable is reported as itself.
  it('leaves a failure that is not skew reported as itself', () => {
    withTempStore((store) => {
      store.open().close();
      corruptStore(store.dbFile, 'truncate', { store });

      const err = errorFrom(() => {
        openLocalDatabase(store.dataDir).close();
      });

      expect(err).toBeDefined();
      expect(err).not.toBeInstanceOf(StoreAheadOfBuildError);
    });
  });
});
