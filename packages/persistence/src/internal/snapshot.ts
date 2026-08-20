import { randomUUID } from 'node:crypto';
import { existsSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';

import { dbSidecars, mkdirOwnerOnlySync, tightenDir, tightenFile, tightenPerms } from '../paths.ts';

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
// staging copy whose mtime has been frozen this long is therefore a leftover
// from a killed process, not a copy another opener has in flight — the bound is
// what lets a reap run without pulling a live staging file out from under its
// writer.
const STALE_PARTIAL_MS = 5 * 60_000;

// The suffix that turns a `backupPath` into its staging area. `backupPath`
// already ends in `.bak`, so a staged copy is `<store>.<tag>.<…>.bak.partial` —
// which is the whole name the reap below matches on, deliberately narrower than
// a bare `.partial` so it can never sweep something else's staging file.
export const SNAPSHOT_STAGING_SUFFIX = '.partial';
const STAGED_NAME_SUFFIX = `.bak${SNAPSHOT_STAGING_SUFFIX}`;

// The copy's fixed name INSIDE the staging directory. Fixed rather than random
// because the directory it sits in already carries the unguessable suffix.
// Exported so the guards that classify what `~/.aka` holds derive this name
// rather than spelling it — `copy` is an ordinary word, and a hand-written copy
// of it in a test would keep matching after a rename here.
export const SNAPSHOT_STAGING_COPY = 'copy';

/**
 * Create the staging area for a snapshot of `backup`: a directory beside the
 * store, owner-only BEFORE SQLite writes anything into it, and the path the
 * copy goes to inside it.
 *
 * The directory is the point. `VACUUM INTO` refuses a target that already
 * exists, so the copy cannot be pre-created at 0600 and then written — it lands
 * at the process UMASK and stays there until the tighten that runs after the
 * copy completes. A `throw` removes it; a KILL cannot, and the plugin opens a
 * store per hook and is killable at its 10 s harness timeout. So a killed hook
 * used to leave a byte-complete copy of the whole prompt corpus at 0644.
 *
 * Nothing can narrow that window at the file, because the file does not exist
 * until SQLite creates it. Enclosing it does: an owner-only directory is
 * untraversable to every other account from the instant it exists, whatever the
 * copy inside it is later created as, and it survives a kill exactly as the
 * copy does.
 */
export function createSnapshotStaging(backup: string): { stage: string; copy: string } {
  const stage = `${backup}${SNAPSHOT_STAGING_SUFFIX}`;
  // SQLite FOLLOWS a symlink at its output path, and a dangling link passes its
  // "output file already exists" check — so a link planted here would send the
  // whole prompt corpus to the link's target. Clearing the path first acts on
  // the link itself, never on what it points at, and the `mkdirSync` that
  // follows then OWNS the name: the copy is written at a path inside a directory
  // this call just created, so it cannot be a link somebody planted in advance.
  rmSync(stage, { recursive: true, force: true });
  mkdirOwnerOnlySync(stage);
  // mkdir's mode is subject to the umask, which only ever clears bits — the
  // tighten is what holds 0700 under one that would have taken some away. The
  // create mode is the half that matters and the half no assertion on a
  // finished snapshot can see, since a completed one removes this directory;
  // `test/internal/snapshot.test.ts` asserts this function directly for that
  // reason, under a permissive umask.
  tightenDir(stage);
  return { stage, copy: join(stage, SNAPSHOT_STAGING_COPY) };
}

/**
 * How long ago a staging leftover was last written, or null when it cannot be
 * told. The directory's own mtime moves only when an entry is added or removed,
 * so a copy that has been growing for minutes leaves it frozen at creation —
 * reading it would age a LIVE copy into staleness. The copy inside is what
 * VACUUM INTO keeps touching, so it is what the bound is measured against; the
 * directory is the fallback for a staging area that never got that far.
 *
 * A leftover written by an older version is a `.partial` FILE rather than a
 * directory, and its own mtime is the right reading. Both shapes are swept, so
 * an upgrade does not strand the copy the previous version left behind.
 */
function idleMs(entry: string): number | null {
  for (const candidate of [join(entry, SNAPSHOT_STAGING_COPY), entry]) {
    try {
      return Date.now() - statSync(candidate).mtimeMs;
    } catch {
      // The copy is absent (a staging dir cut short before VACUUM INTO created
      // it, or a legacy file-shaped leftover) — fall through to the entry.
    }
  }
  return null;
}

/**
 * Remove abandoned staging areas left beside the store.
 *
 * `snapshotStore` writes its copy inside a `<backup>.bak.partial` directory and
 * renames it into place; a throw clears it, but a KILL — a hook cut off at its
 * timeout, mid `VACUUM INTO` — cannot, and nothing else reaps it:
 * `discardStore` clears only the store and its sidecars. On the plugin path (a
 * store opened per hook, killable at its timeout) that is one leftover per
 * attempt, each up to store size.
 *
 * Runs on EVERY open, not only before a snapshot. The snapshot paths are
 * reached by a migration or a foreign-lineage reset, so hanging the sweep off
 * them alone meant a machine that never did either kept its leftover
 * indefinitely — the copy holds the same prompt corpus as the store, so
 * "indefinitely" was the half that mattered most.
 *
 * Covers every `<store>.*.bak.partial` beside the store, so both the `.legacy.`
 * and `.pre-drop.` names, and both shapes: the directory this version stages
 * into and the bare `.partial` FILE an older version left. Age-bounded because
 * a concurrent opener's copy in flight shares the prefix: only a leftover idle
 * for STALE_PARTIAL_MS is treated as abandoned. A pid bound would be wrong —
 * the name is random-suffixed, not pid-scoped. Best-effort throughout: it runs
 * on the fail-open open path and must never throw.
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
    if (!name.startsWith(prefix) || !name.endsWith(STAGED_NAME_SUFFIX)) continue;
    const staging = join(dir, name);
    try {
      const idle = idleMs(staging);
      if (idle !== null && idle > STALE_PARTIAL_MS) {
        // `recursive` covers the directory shape; `force` covers a leftover
        // that raced away between the reading above and here.
        rmSync(staging, { recursive: true, force: true });
      }
    } catch {
      // best-effort: raced away by another opener, or unremovable — leave it
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
 * The copy lands inside a `.bak.partial` staging DIRECTORY and is renamed into
 * place only once it is complete, so a snapshot cut short by a kill rather than
 * a throw (a hook killed at its timeout) leaves a staging directory, never a
 * truncated file that reads as a usable backup at recovery time.
 *
 * That directory is created owner-only before SQLite writes anything into it,
 * which is the only way to cover the copy for the whole time it is being
 * written: `VACUUM INTO` refuses an existing target, so the copy itself cannot
 * be pre-created at 0600, and a kill leaves whatever the umask gave it. An
 * enclosing 0700 directory is untraversable from the first instant and survives
 * the kill with the copy (see createSnapshotStaging).
 *
 * Throws on failure, having removed its own staging directory.
 */
export function snapshotStore(db: DatabaseSync, backup: string): void {
  // Built before the try so a failure to create the staging area throws with
  // nothing to clean up — there is no stage to remove until this returns.
  const { stage, copy } = createSnapshotStaging(backup);
  try {
    db.prepare('VACUUM INTO ?').run(copy);
    // VACUUM INTO writes a brand-new file at the process umask (typically 0644),
    // but it is a full copy of the prompt corpus, so hold it to the store's own
    // 0600. This runs before the rename, which carries the inode and its mode
    // across, so the PUBLISHED backup is always 0600. The copy is only ever
    // reachable through the owner-only directory above until then.
    tightenFile(copy);
    renameSync(copy, backup);
  } catch (error) {
    // A partial copy left behind would read as a usable backup, so drop it. A
    // cleanup failure never replaces the error that caused it.
    try {
      rmSync(stage, { recursive: true, force: true });
    } catch {
      // nothing to undo: no backup was published either way
    }
    throw error;
  }
  // The published backup is out; the staging directory has nothing left in it.
  // Outside the try because a removal failure here must not be mistaken for a
  // failed snapshot — the copy is already at `backup`.
  try {
    rmSync(stage, { recursive: true, force: true });
  } catch {
    // best-effort: an empty directory the next reap will clear
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
