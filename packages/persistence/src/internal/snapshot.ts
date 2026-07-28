import { randomUUID } from 'node:crypto';
import { existsSync, renameSync, rmSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';

import { dbSidecars, tightenFile, tightenPerms } from '../paths.ts';

/**
 * A backup path beside the store: `<file>.<tag>.<millis>.<random>.bak`.
 *
 * The random suffix is load-bearing twice over. Millisecond time alone is not
 * unique — the plugin hooks, the CLI and the dashboard all open the same store,
 * so two of them entering the same recovery path can mint the same name in one
 * millisecond, and `VACUUM INTO` refuses a target that already exists. It must
 * also be unguessable: SQLite follows a symlink at its output path, so a
 * predictable name in a loosely-permissioned data dir would let a planted link
 * redirect a full copy of the prompt corpus somewhere else.
 */
export function backupPath(file: string, tag: string): string {
  return `${file}.${tag}.${String(Date.now())}.${randomUUID().slice(0, 8)}.bak`;
}

/**
 * Snapshot the open store behind `db` to `backup`.
 *
 * `VACUUM INTO` writes a consistent, fully-materialized SINGLE-file copy through
 * its own read transaction — no `-wal`/`-shm` sidecars — so it captures committed
 * WAL frames a raw copy of the main file would miss, without needing the WAL
 * checkpointed. SQLite checkpoints only when the LAST connection closes, so under
 * the product's multi-process open model a close-time checkpoint does not run at
 * all and those frames stay in the `-wal`. The bound parameter avoids any
 * path-quoting hazard.
 *
 * The copy lands on a `.partial` sibling and is renamed into place only once it
 * is complete, so:
 *  - a snapshot cut short by a kill rather than a throw (a hook killed at its
 *    timeout) leaves a `.partial`, never a truncated file that reads as a usable
 *    backup at recovery time;
 *  - the rename REPLACES whatever sits at `backup` — a symlink included —
 *    instead of writing through it, and `tightenFile` then has a real file to
 *    hold at 0600 rather than declining on a link.
 *
 * Throws on failure, having removed its own partial file.
 */
export function snapshotStore(db: DatabaseSync, backup: string): void {
  const partial = `${backup}.partial`;
  try {
    db.prepare('VACUUM INTO ?').run(partial);
    renameSync(partial, backup);
  } catch (error) {
    // A partial copy left behind would read as a usable backup, so drop it. A
    // cleanup failure never replaces the error that caused it.
    try {
      rmSync(partial, { force: true });
    } catch {
      // nothing to undo: no backup was published either way
    }
    throw error;
  }
  // VACUUM INTO writes a brand-new file at the process umask (typically 0644),
  // but it is a full copy of the prompt corpus, so tighten it to the store's
  // own 0600.
  tightenFile(backup);
}

/**
 * Move the whole store aside to `backup` without copying it: the main file plus
 * every sidecar that exists, each renamed to the matching `<backup>-wal` /
 * `-shm` / `-journal`. SQLite derives the WAL name from the main filename, so
 * the moved set reopens as one complete store, committed frames included —
 * which renaming the main file alone would strand.
 *
 * The recovery path for a store `snapshotStore` cannot copy (a corrupt page, no
 * room for a second copy): a rename needs neither a readable page image nor free
 * space. A sidecar that cannot be moved is removed instead — a fresh store at
 * the original path must never inherit a stale `-wal`.
 *
 * The caller must have closed its handle first: on Windows a live handle blocks
 * the rename.
 */
export function moveStoreAside(file: string, backup: string): void {
  renameSync(file, backup);
  for (const sidecar of dbSidecars(file)) {
    if (!existsSync(sidecar)) continue;
    try {
      renameSync(sidecar, `${backup}${sidecar.slice(file.length)}`);
    } catch {
      rmSync(sidecar, { force: true });
    }
  }
  // The moved files keep the original store's (possibly loose) modes, and they
  // hold the same prompt content as the live store.
  tightenPerms(backup);
}
