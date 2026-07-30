import { randomUUID } from 'node:crypto';
import { existsSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

import { dbSidecars, tightenFile, tightenPerms } from '../paths.ts';

/**
 * A backup path beside the store: `<file>.<tag>.<millis>.<random>.bak`.
 *
 * The random suffix is load-bearing twice over. Millisecond time alone is not
 * unique — the plugin hooks, the CLI and the dashboard all open the same store,
 * so two of them entering the same recovery path can mint the same name in one
 * millisecond, and `VACUUM INTO` refuses a target that already exists. It also
 * keeps both this path and the `.partial` beside it unguessable, which is the
 * first line of defence against a planted symlink (see snapshotStore).
 */
export function backupPath(file: string, tag: string): string {
  return `${file}.${tag}.${String(Date.now())}.${randomUUID().slice(0, 8)}.bak`;
}

// A snapshot copy of a local store finishes in well under this, and VACUUM INTO
// keeps touching the file as it writes, so a live copy's mtime stays recent. A
// `.partial` whose mtime has been frozen this long is therefore a leftover from
// a killed process, not a copy another opener has in flight — the bound is what
// lets a reap run without pulling a live staging file out from under its writer.
const STALE_PARTIAL_MS = 5 * 60_000;

/**
 * Remove abandoned `.partial` staging files left beside the store.
 *
 * `snapshotStore` writes its copy to a `<backup>.partial` and renames it into
 * place; a throw removes it, but a KILL — a hook cut off at its timeout, mid
 * `VACUUM INTO` — cannot, and nothing else reaps it: `discardStore` clears only
 * the store and its sidecars. On the plugin path (a store opened per hook,
 * killable at its timeout) that is one leftover per attempt, each up to store
 * size and at the process umask.
 *
 * Runs before a snapshot, over every `<store>.*.bak.partial` beside the store,
 * so it covers both the `.legacy.` and `.pre-drop.` names. Age-bounded because a
 * concurrent opener's copy in flight shares the prefix: only a `.partial` whose
 * mtime has not moved for STALE_PARTIAL_MS is treated as abandoned. A pid bound
 * would be wrong — the name is random-suffixed, not pid-scoped. Best-effort
 * throughout: it runs on the fail-open open path and must never throw.
 */
export function reapStalePartials(file: string): void {
  const dir = dirname(file);
  const prefix = `${basename(file)}.`;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return; // the data dir is unreadable or absent — nothing to sweep
  }
  for (const name of entries) {
    if (!name.startsWith(prefix) || !name.endsWith('.bak.partial')) continue;
    const partial = join(dir, name);
    try {
      if (Date.now() - statSync(partial).mtimeMs > STALE_PARTIAL_MS) {
        rmSync(partial, { force: true });
      }
    } catch {
      // best-effort: raced away by another opener, or unstattable — leave it
    }
  }
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
 * is complete, so a snapshot cut short by a kill rather than a throw (a hook
 * killed at its timeout) leaves a `.partial`, never a truncated file that reads
 * as a usable backup at recovery time.
 *
 * Throws on failure, having removed its own partial file.
 */
export function snapshotStore(db: DatabaseSync, backup: string): void {
  const partial = `${backup}.partial`;
  try {
    // SQLite FOLLOWS a symlink at its output path, and a dangling link passes
    // its "output file already exists" check — so a link planted here would send
    // the whole prompt corpus to the link's target. Unlink acts on the link
    // itself, never on what it points at. The rename below does not cover this:
    // it protects the `backup` path, and `partial` is the path actually written.
    rmSync(partial, { force: true });
    db.prepare('VACUUM INTO ?').run(partial);
    // VACUUM INTO writes a brand-new file at the process umask (typically 0644),
    // but it is a full copy of the prompt corpus, so hold it to the store's own
    // 0600. This runs before the rename, which carries the inode and its mode
    // across, so the PUBLISHED backup is always 0600. It does NOT make the copy
    // itself owner-only: the file exists at the umask for the whole VACUUM INTO
    // above, so a process killed DURING the copy still leaves a 0644 `.partial`
    // — the widest window, and the one reapStalePartials cleans up on a later
    // open. The tighten cannot run any earlier: the file does not exist until
    // VACUUM INTO creates it.
    tightenFile(partial);
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
}

/**
 * Move the whole store aside to `backup` without copying it: the main file plus
 * every sidecar, each renamed to the matching `<backup>-wal` / `-shm` /
 * `-journal`. SQLite derives the WAL name from the main filename, so the moved
 * set reopens as one complete store, committed frames included — which renaming
 * the main file alone would strand.
 *
 * The recovery path for a store `snapshotStore` cannot copy (a corrupt page, no
 * room for a second copy): a rename needs neither a readable page image nor free
 * space. A sidecar that cannot be moved is removed instead — a fresh store at
 * the original path must never inherit a stale `-wal`. If it can be neither
 * moved nor removed, every rename is undone and the throw leaves the store
 * exactly where it was, rather than leaving a stale sidecar with no main file
 * for the reopen to pair a brand-new store with.
 *
 * The caller must have closed its handle first: on Windows a live handle blocks
 * the rename.
 */
export function moveStoreAside(file: string, backup: string): void {
  // Each entry undoes one completed rename, newest first.
  const undo: [from: string, to: string][] = [];
  renameSync(file, backup);
  undo.push([backup, file]);
  try {
    for (const sidecar of dbSidecars(file)) {
      const moved = `${backup}${sidecar.slice(file.length)}`;
      try {
        renameSync(sidecar, moved);
        undo.push([moved, sidecar]);
      } catch {
        // Absent, or held open by another process. Either way it must not be
        // left for a fresh store at the original path to adopt.
        rmSync(sidecar, { force: true });
      }
    }
  } catch (error) {
    for (const [from, to] of undo.reverse()) {
      try {
        renameSync(from, to);
      } catch {
        // Best effort — the throw below is what the caller acts on.
      }
    }
    throw error;
  }
  // The moved files keep the original store's (possibly loose) modes, and they
  // hold the same prompt content as the live store.
  tightenPerms(backup);
}

/**
 * Drop the original store — main file plus its now-stale sidecars — once
 * `backup` holds a snapshot of it.
 *
 * `force` covers only a path that is already gone. If the MAIN file cannot be
 * cleared at all (a live handle on Windows) the reset has not happened: the
 * original is still whole, the snapshot just taken is redundant, and dropping it
 * is what keeps a failing reset from orphaning a full-size copy on every attempt
 * — a bare rename left nothing behind when it failed, and this matches that.
 *
 * Once the main file IS gone, though, `backup` is the only remaining copy, so a
 * later failure in the sidecar loop (a `-shm` mapping that outlives its process
 * on Windows, a root-owned sidecar on POSIX) must NOT drop it. The catch removes
 * the backup only while the original still exists; past that point orphaning the
 * copy beats losing the store from both places at once.
 */
export function discardStore(file: string, backup: string): void {
  try {
    rmSync(file, { force: true });
    for (const sidecar of dbSidecars(file)) {
      rmSync(sidecar, { force: true });
    }
  } catch (error) {
    // Only an untouched original makes the backup redundant. Once the main file
    // is gone the backup is the last copy — keep it; orphaned beats lost.
    if (existsSync(file)) {
      try {
        rmSync(backup, { force: true });
      } catch {
        // A cleanup failure never replaces the error that caused it.
      }
    }
    throw error;
  }
}
