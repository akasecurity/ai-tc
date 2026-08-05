import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { DB_FILENAME } from '@akasecurity/persistence';

function errnoCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null && 'code' in err && typeof err.code === 'string'
    ? err.code
    : undefined;
}

/**
 * The raw bytes of everything the store wrote under `dir` — the main DB plus
 * every other file beside it — so an at-rest leak is caught wherever it landed.
 * Callers assert against it with `not.toContain(rawValue)`.
 *
 * Reading the DIRECTORY rather than a hardcoded name list is what makes this
 * cover more than the `-wal`/`-shm` pair. SQLite writes an `aka.db-journal`
 * instead wherever WAL silently no-ops — DrvFs `/mnt/c` and some network mounts,
 * per `dbSidecars` in `packages/persistence/src/paths.ts` — so a WAL-only scan
 * reads files the data did not go to and reports clean. A migration
 * (`aka.db.pre-drop.<ts>.<rand>.bak`) and the foreign-lineage reset
 * (`aka.db.legacy.<ts>.<rand>.bak`) leave real copies in the same directory, and
 * a snapshot killed part-way leaves a `.bak.partial` beside them.
 *
 * Files only: `isFile()` skips directories, and nothing writes one under the
 * data dir today (`paths.ts`, `fingerprint.ts` and `warn-era-cap.ts` all write
 * flat). A future subdirectory would need this to recurse — it is not covered
 * for free the way a future sibling file is.
 *
 * Nothing here is lenient, because an empty string contains no secret: any
 * silent shortfall turns every `not.toContain` caller into a no-op that reports
 * clean. A missing store throws, and so does a failed read.
 *
 * `read` is injected so the failed-read branch is reachable on every platform.
 * A real permission denial needs POSIX modes, which Windows does not have — and
 * Windows is where a sharing violation on an open store file is most likely, so
 * that branch must not be pinned only where it is easy to provoke.
 */
export function storeBytes(dir: string, read: (path: string) => Buffer = readFileSync): string {
  const names = readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
  if (!names.includes(DB_FILENAME)) {
    throw new Error(
      `no ${DB_FILENAME} under ${dir} — the at-rest scan is not reading the real store`,
    );
  }
  const parts: Buffer[] = [];
  for (const name of names) {
    try {
      parts.push(read(join(dir, name)));
    } catch (err) {
      // One tolerated fault: ENOENT on a SIBLING, which is the short-lived tmp
      // an atomic write unlinks the moment it publishes — `${file}.<pid>.tmp`
      // from `writeOwnerOnlyFileSync` (the rename twin, which rotates
      // `exception.key`) or `${file}.<pid>.<tid>.new` from
      // `createOwnerOnlyFileSync` (the link twin, which mints it) — vanishing
      // between the listing and the read. Both write raw key material into this
      // very directory, so the tolerance is on the ENOENT, never on the name.
      //
      // Everything else rethrows. `aka.db` is never atomically rewritten, so an
      // ENOENT on it is as much a fault as a permission denial; and a swallowed
      // failure on any file hands back the others alone, which carry none of the
      // raw — the caller then reports clean on a store it never read.
      if (name === DB_FILENAME || errnoCode(err) !== 'ENOENT') throw err;
    }
  }
  return Buffer.concat(parts).toString('latin1');
}
