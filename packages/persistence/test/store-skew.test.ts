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
import { describeStoreSkew, StoreAheadOfBuildError } from '../src/store-skew.ts';
import { errorFrom } from './helpers/errors.ts';
import { corruptStore } from './helpers/fault-injection.ts';
import { withTempStore } from './helpers/temp-store.ts';

// Lexically past every real tag, so it sorts last and can never collide with one
// a future migration adds.
const FUTURE_TAG = '9999_from_a_newer_build';

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
