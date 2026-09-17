// Is the store ahead of the binary opening it?
//
// `applyMigrations` has nothing to apply to a store whose history already
// contains its own, so it skips — and the repository constructors then prepare
// against a schema this build does not know. What comes back is a bare SQLite
// error (`cannot UPSERT a view`, from a build predating the migration that
// turned `events`/`findings` into compat views; a missing column from one
// predating an ALTER), thrown while the store is still being wired and so
// indistinguishable from a store that genuinely cannot be opened.
//
// The two need different answers. An unopenable store is repaired by looking at
// the file; a store that is merely NEWER is intact, is read correctly by every
// up-to-date surface on the machine, and is repaired by updating the stale one.
// Advice to move it aside is data loss in the second case — the prompt corpus
// is destroyed to work around a binary that is behind.
import type { DatabaseSync } from 'node:sqlite';

import { SQLITE_MIGRATIONS } from '@akasecurity/schema';

/** A store's migration history, as far as it exceeds this build's. */
export interface StoreSkew {
  /** `PRAGMA user_version` — the store's own count, for the report only. */
  readonly storeVersion: number;
  /** How many migrations this build defines. */
  readonly buildVersion: number;
  /** Ledger tags present in the store that this build does not define. */
  readonly unknownTags: readonly string[];
}

/**
 * The skew, or `null` when the store is not ahead.
 *
 * DECIDED ON TAGS, NEVER ON THE COUNT. `user_version` is stamped write-only so
 * that downgrading to an older count-based build stays a no-op, which means a
 * store can carry a number past this build's ledger while this build knows
 * every tag in it — reading that as skew would report a perfectly ordinary
 * store as written by a newer binary. Tags are also what survive the
 * renumbering the ledger exists to tolerate. The count is carried along for the
 * message and decides nothing.
 *
 * Best-effort by construction: this runs on a failure path, over a handle whose
 * store has already refused to open once, so every way of asking (no ledger
 * table, an unreadable page, a handle closed further up) answers "not ahead"
 * rather than throwing a second error over the first.
 */
export function describeStoreSkew(db: DatabaseSync): StoreSkew | null {
  try {
    const known = new Set(SQLITE_MIGRATIONS.map((m) => m.tag));
    const unknownTags = (db.prepare('SELECT tag FROM migration_ledger').all() as { tag: string }[])
      .map((r) => r.tag)
      .filter((tag) => !known.has(tag))
      .sort();
    if (unknownTags.length === 0) return null;

    const storeVersion = (db.prepare('PRAGMA user_version').get() as { user_version: number })
      .user_version;
    return { storeVersion, buildVersion: SQLITE_MIGRATIONS.length, unknownTags };
  } catch {
    // Nothing here is worth failing over: the caller already has the error that
    // matters and this only decides how to describe it.
    return null;
  }
}

/**
 * The store could not be opened, and the reason is that this binary is behind
 * it.
 *
 * Carries the underlying SQLite failure as `cause` — a maintainer still needs
 * the statement that actually threw, while nothing above this has to read it to
 * tell the user something true.
 */
export class StoreAheadOfBuildError extends Error {
  readonly storeVersion: number;
  readonly buildVersion: number;
  readonly unknownTags: readonly string[];

  constructor(skew: StoreSkew, cause: unknown) {
    super(
      `[aka] the local store was written by a newer AKA build than this one: it carries ` +
        `migration(s) ${skew.unknownTags.join(', ')} that this build does not define ` +
        `(store schema ${String(skew.storeVersion)}, this build ${String(skew.buildVersion)}). ` +
        `The store is intact and needs no repair — update AKA so every surface on this ` +
        `machine is on one version line.`,
      { cause },
    );
    this.name = 'StoreAheadOfBuildError';
    this.storeVersion = skew.storeVersion;
    this.buildVersion = skew.buildVersion;
    this.unknownTags = skew.unknownTags;
  }
}
