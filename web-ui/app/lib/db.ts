import 'server-only';

import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  StoreAheadOfBuildError,
} from '@akasecurity/persistence';

// The local store the plugin/CLI write — ~/.aka/data/aka.db, resolved by the
// shared ~/.aka layout module in @akasecurity/persistence (the same one the plugin SDK
// and CLI use, so the paths can never drift). Location comes from homedir(),
// not process.env.

// openLocalDatabase opens a WAL handle and runs migrations + seedDefaults on every
// call, so memoize a singleton across requests — and across dev HMR reloads, via
// globalThis, so we don't leak file handles. node:sqlite makes this module
// server-only (the `server-only` import fails the build if a client imports it).
const store = globalThis as unknown as { __akaDb?: LocalDatabase };

export function db(): LocalDatabase {
  if (store.__akaDb) return store.__akaDb;
  const database = openLocalDatabase(dataDir());
  // Purge the RETIRED demo/sample dataset once, when the singleton is first
  // created — stores from previously shipped builds may still carry sample rows;
  // the product no longer seeds any. Once per process (not per force-dynamic
  // render) so no per-request write can contend with the plugin's WAL writes
  // (SQLITE_BUSY). Idempotent + fail-open; real rows are never touched.
  database.purgeSampleData();
  store.__akaDb = database;
  return database;
}

/**
 * What a reader may be told about a store written by a NEWER AKA build.
 *
 * EVERY FIELD IS SCHEMA-DERIVED, and that is the whole point of the shape. A
 * store-open failure arrives as an Error whose message can quote the statement
 * that failed, and these pages read a store holding scanned content — which is
 * why `app/(app)/error.tsx` renders the digest and never `error.message`. A
 * migration tag and two ledger counts come from this build's own source and the
 * store's `migration_ledger`; none of them can carry a captured value. So this
 * is the only part of such a failure that may reach a page.
 */
export interface StoreVersionSkew {
  readonly unknownTags: readonly string[];
  readonly storeVersion: number;
  readonly buildVersion: number;
}

/**
 * Is the store this dashboard reads newer than this dashboard?
 *
 * The dashboard is the one surface where the store-open failure cannot speak
 * for itself. A hook writes to a terminal and the CLI prints `err.message`, but
 * a throw inside a Server Component renders the error boundary — which shows a
 * digest by design, and which in production receives a redacted message anyway.
 * A user whose dashboard is a stale binary would see "Something went wrong" and
 * an opaque digest, with nothing to act on and no hint that the store is fine.
 *
 * Returns `null` for a healthy store AND for every failure that is not skew, so
 * an unreadable store still reaches the ordinary boundary: this narrows what is
 * reported, it does not become a catch-all that swallows real faults.
 */
export function storeVersionSkew(): StoreVersionSkew | null {
  try {
    db();
    return null;
  } catch (err) {
    if (!(err instanceof StoreAheadOfBuildError)) return null;
    return {
      unknownTags: [...err.unknownTags],
      storeVersion: err.storeVersion,
      buildVersion: err.buildVersion,
    };
  }
}

/**
 * Release the store this module holds, if it holds one.
 *
 * Exported for the one caller that needs it: a test suite REMOVING the directory
 * the store lives in. Windows refuses to delete a file another handle holds open
 * (EPERM) where POSIX unlinks it and carries on, so a suite that redirects the
 * home, renders a page and then removes that home again cannot do so while this
 * module still holds the store it opened there. See test/helpers/temp-home.ts.
 *
 * Nothing in the request path calls this: the singleton above is deliberate and
 * production never moves its home.
 */
export function closeStore(): void {
  const held = store.__akaDb;
  if (!held) return;
  // Cleared BEFORE the close, so a close that throws cannot leave a handle
  // nobody can reach still recorded as the live one.
  store.__akaDb = undefined;
  try {
    held.close();
  } catch {
    // Cleanup: already closed, or a close that failed. Neither leaves the caller
    // anything useful to do.
  }
}
