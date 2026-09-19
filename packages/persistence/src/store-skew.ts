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
//
// TWO QUESTIONS DECIDE THE RE-DESCRIPTION, and the ledger answers only the
// first: is the store ahead, and is this the kind of failure a schema this
// build does not know can produce. "Ahead" on its own is not a cause — an
// ahead-but-compatible store fails for the same environmental reasons any
// store does, and describing a chmod'd or contended file as "intact, update
// AKA" would be false on exactly the machines this exists for.
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

// SQLITE_ERROR — the generic code every schema mismatch reports: `cannot UPSERT
// a view`, `no such column`, `no such table` and a column count that no longer
// matches all arrive as 1. node:sqlite gives every SQLite failure the same
// `code` ('ERR_SQLITE_ERROR'), so only `errcode` separates one from another.
const SQLITE_ERROR = 1;
// SQLITE_CONSTRAINT — a newer schema refusing a write this build still makes.
// The NOT NULL column a newer migration added is the one that bites first: the
// INSERT this build prepares omits it, and the engine refuses.
const SQLITE_CONSTRAINT = 19;

/**
 * Whether a failure is one a schema this build does not know can produce.
 *
 * The gate on `StoreAheadOfBuildError`, and the reason "the store is ahead" is
 * not a cause on its own: a chmod'd store answers SQLITE_READONLY and a
 * contended one SQLITE_BUSY whatever its ledger says, and re-describing either
 * as "the store is intact — update AKA" would be false, would bury the result
 * code the caller needs, and would repeat that noise on every hook that loses
 * the race.
 *
 * An ALLOWLIST, not the denylist of codes that name the store or its host
 * (BUSY, LOCKED, READONLY, IOERR, FULL, CORRUPT, NOTADB, CANTOPEN). Both keep
 * those out; they differ on the codes nobody has thought about yet, and the
 * re-description is the claim that has to be earned — an unrecognised failure
 * keeps the message every other failure gets.
 *
 * The two codes here are the shapes a newer schema produces. The first was
 * measured in the field — `cannot UPSERT a view`, from a build predating the
 * migration that turned `events`/`findings` into compat views; the second is
 * the refusal the NOT NULL column a newer migration added produces, which no
 * store in this suite reaches but which no longer needs `cause` read to be
 * told apart from a damaged file.
 */
export function isSchemaShapedFailure(err: unknown): boolean {
  // `errcode` carries the EXTENDED code — the primary code plus a refinement in
  // its high bits, so SQLITE_READONLY_DIRECTORY is 1544 and SQLITE_BUSY_SNAPSHOT
  // is 517 — hence the low byte. Anything that is not an error at all (a
  // repository constructor throwing a TypeError, a bare string) carries no code
  // and is not this.
  const code = (err as { errcode?: unknown } | null | undefined)?.errcode;
  if (typeof code !== 'number') return false;
  const primary = code & 0xff;
  return primary === SQLITE_ERROR || primary === SQLITE_CONSTRAINT;
}

/**
 * The store could not be opened, and what refused it is the schema this build
 * does not know — the store is ahead AND the failure is one that explains.
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
