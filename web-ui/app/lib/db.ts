import 'server-only';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';

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
