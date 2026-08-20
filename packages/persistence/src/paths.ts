import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { threadId } from 'node:worker_threads';

// The shared SQLite store holds prompt/file content and masked findings, so the
// directory is owner-only and the DB files are written 0600. This module is the
// single definition of the ~/.aka layout and its modes; the plugin SDK's
// data-dir module re-exports them from here rather than keeping a second copy,
// so every writer under ~/.aka applies the same modes.
//
// These POSIX modes are the ONLY at-rest control on the store (there is no
// encryption). They are a no-op on platforms without POSIX modes (Windows),
// where they provide no protection — see the "Data at rest" note in SECURITY.md.
export const DATA_DIR_MODE = 0o700;
export const DATA_FILE_MODE = 0o600;

// The single SQLite database file every plugin shares, under the caller-supplied
// data dir (e.g. ~/.aka/data computed by the SDK).
export const DB_FILENAME = 'aka.db';

// True when the path's FINAL component is a symlink. An lstat failure — most
// often an absent target, e.g. a not-yet-created -wal sidecar — reports false,
// so the caller's own absent-target handling still decides what happens.
function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

// chmod `path` to `mode`, best-effort and silent: swallow every failure so a
// permission glitch on a fail-open hot path (every plugin hook re-tightens the
// base dir + settings.json) can neither throw nor spam stderr. A filesystem that
// rejects chmod — some SMB/NFS/WSL mounts, a root-owned file — is surfaced once,
// where it is actionable, by `aka init` (see looseStorePaths), not on every hook.
//
// Never chmods THROUGH a symlink. On the self-heal paths (loadConfig / aka init)
// `path` is attacker-controllable in the loose-~/.aka state this repo exists to
// repair, and chmod follows links, so a planted symlink would otherwise let a
// tighten reach an arbitrary target: at a file that means an arbitrary chmod, and
// at a store DIRECTORY it means locking a victim-owned shared directory to
// owner-only with no diagnostic. Every legitimate store artifact — the base dir,
// settings/, data/, keys/, settings.json, the key, the db and its sidecars — is a
// real inode.
//
// Only the FINAL component is checked, deliberately: a real inode this code
// created inside a symlinked home is still tightened, so a home a user chose to
// symlink (a dotfiles manager, another volume) keeps the store's at-rest modes
// instead of silently losing them.
//
// The check is an lstat, so it is NOT race-free: an attacker who swaps a real
// path for a symlink between the lstat and the chmod still reaches the target.
// Closing that needs openSync(O_NOFOLLOW) + fchmod, which cannot cover the
// directory and file cases uniformly on every platform this ships to. The lstat
// mirrors what tightenFile has always done and raises the bar without removing
// the race — the precondition for winning it is write access to ~/.aka, which is
// the loose state this repair exists to leave behind.
function chmodBestEffort(path: string, mode: number): void {
  if (isSymlink(path)) return;
  try {
    chmodSync(path, mode);
  } catch {
    // best-effort: absent target, a platform without POSIX modes (Windows), or a
    // filesystem/owner that rejects chmod — never break the caller.
  }
}

// 0700 on a data directory. Best-effort and never through a symlink (see
// chmodBestEffort) — the single place the dir-mode policy lives, so the sync and
// async dir paths can't diverge.
export function tightenDir(dir: string): void {
  chmodBestEffort(dir, DATA_DIR_MODE);
}

/**
 * Create `dir` owner-only from the instant it exists — the directory twin of
 * {@link writeExclusiveOwnerOnlySync}, and load-bearing for the same reason.
 *
 * Every caller follows this with a `tightenDir`, which is deliberate: `mkdir`'s
 * mode is subject to the umask, and a umask only ever CLEARS bits, so one that
 * would take some away (0o277 and up) leaves a directory this create alone
 * cannot hold at 0700. That belt-and-suspenders pair is also why the create mode
 * cannot be defended by looking at the finished directory — the tighten repairs
 * the end state, so deleting the `mode` here leaves every post-hoc assertion in
 * the workspace green while the directory is briefly traversable by every
 * account on the machine. It matters most where something is written INTO the
 * directory during that window: the snapshot staging area is a full copy of the
 * prompt corpus, and the rotation lock is stamped immediately after it is made.
 *
 * `paths.test.ts` asserts this function directly, under a permissive umask and
 * with no tighten in the way, so the create mode has one test of its own that a
 * deletion reddens.
 *
 * `recursive` is passed through rather than fixed: the layout dirs are created
 * parents-and-all, while the lock and the staging area need `mkdir`'s EEXIST to
 * propagate — that refusal is how the lock picks exactly one winner.
 */
export function mkdirOwnerOnlySync(dir: string, recursive = false): void {
  mkdirSync(dir, { recursive, mode: DATA_DIR_MODE });
}

// Create the data dir owner-only, tightening it even if it pre-existed with
// looser permissions. chmod is best-effort (a no-op on platforms without POSIX
// modes, e.g. Windows) and must never break the fail-open open path.
//
// mkdir does not follow the final symlink either: at a path that is already a
// symlink to a directory it is a silent no-op, and at one resolving nowhere it
// raises ENOENT rather than creating the target. Together with the tighten's own
// guard, a symlinked store directory is therefore used as-is, under the target's
// permissions — the store still opens (a hook must not break on a hostile or
// unusual home), and `aka init` names the link and its target, since inheriting
// those permissions silently is the part a user has to know about.
export function ensureDataDirSync(dir: string): void {
  mkdirOwnerOnlySync(dir, true);
  tightenDir(dir);
}

// The sidecar files SQLite keeps next to a database file: -wal/-shm in WAL mode,
// -journal in the rollback (DELETE/TRUNCATE) modes it falls back to when WAL is
// unavailable (e.g. DrvFs `/mnt/c` and some network mounts silently no-op WAL).
export function dbSidecars(file: string): string[] {
  return [`${file}-wal`, `${file}-shm`, `${file}-journal`];
}

// 0600 on a single file — the DB alone, the exception key, a settings file, or a
// store backup copy. Best-effort and never through a symlink (see
// chmodBestEffort).
export function tightenFile(file: string): void {
  chmodBestEffort(file, DATA_FILE_MODE);
}

// 0600 on the DB and its sidecars — they hold prompt/file content and masked
// findings. Best-effort: a no-op where POSIX modes don't apply, never through a
// symlink (a sidecar path is as plantable as settings.json in the loose-~/.aka
// state), and any given sidecar may not exist (only the ones the active journal
// mode created do).
export function tightenPerms(file: string): void {
  for (const path of [file, ...dbSidecars(file)]) chmodBestEffort(path, DATA_FILE_MODE);
}

/**
 * Create `file` with `data`, owner-only from the instant it exists.
 *
 * The single place a store file is BROUGHT INTO BEING, so the create mode lives
 * in one place rather than beside each writer. `mode` is applied by the create
 * itself, so the file is never briefly world-readable with its contents already
 * in it — which a `writeFileSync` + `chmod` pair cannot promise, and which is
 * the half a reader cannot see afterwards because the end state is identical
 * either way. That is also why the mode is not defensible by any assertion on a
 * published file: every caller below re-tightens after publishing, so dropping
 * the `mode` here leaves every end state correct. `paths.test.ts` asserts this
 * function directly, under a permissive umask and with no tighten in the way, so
 * the create mode has one test of its own that a deletion reddens.
 *
 * `wx` (O_EXCL) is the other half of the contract and is equally load-bearing:
 * it refuses to follow a symlink, so a leftover or planted link at `file` can
 * neither be written through nor have its target chmod'd, and it picks exactly
 * one winner when two callers race the same path.
 */
export function writeExclusiveOwnerOnlySync(file: string, data: string): void {
  writeFileSync(file, data, { mode: DATA_FILE_MODE, flag: 'wx' });
}

// Atomic owner-only write of `file`: write a sibling tmp, then rename it into
// place. The caller must have created the parent dir (ensureDataDirSync).
//
// The tmp name is per-process (`${file}.<pid>.tmp`), so two writers on one
// settings.json — /aka:setup and the dashboard's Settings save — never share a
// tmp inode and can't publish each other's half-written file. A stale same-pid
// tmp (an earlier crash) is removed first, then the write uses `wx` (O_EXCL): it
// creates the tmp exclusively and, critically, REFUSES to follow a symlink, so a
// leftover or planted symlink at the tmp path can never be written through or
// have its target chmod'd. The `finally` removes the tmp on any failure so an
// interrupted per-process write leaves nothing behind (it is a no-op after a
// successful rename). The rename publishes an owner-only inode; the trailing
// tighten re-asserts 0600 belt-and-suspenders.
export function writeOwnerOnlyFileSync(file: string, data: string): void {
  const tmp = `${file}.${String(process.pid)}.tmp`;
  try {
    rmSync(tmp, { force: true });
  } catch {
    // best-effort: unlink removes a leftover/symlinked tmp without touching its
    // target; the exclusive `wx` create below still refuses to follow a symlink.
  }
  try {
    writeExclusiveOwnerOnlySync(tmp, data);
    renameSync(tmp, file);
  } finally {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort cleanup — never mask the original write/rename error.
    }
  }
  tightenFile(file);
}

/**
 * What is sitting at a path that a creation-exclusive publish found occupied but
 * could not then read back. An lstat failure is reported as 'unknown' rather
 * than folded into 'gone': telling an operator the file "was removed" when the
 * truth is that its directory cannot be read sends them looking for the wrong
 * thing, and the lstat error is the one fact that narrows it — so it travels
 * with the verdict and ends up as the thrown error's `cause`.
 *
 * Shared by both machine-local keys, which classify the same three states and
 * differ only in the wording they put on them.
 */
export type Occupant =
  { kind: 'symlink' | 'gone'; cause?: undefined } | { kind: 'unknown'; cause: unknown };

export function classifyOccupant(file: string): Occupant {
  try {
    if (lstatSync(file).isSymbolicLink()) return { kind: 'symlink' };
    // lstat sees a non-symlink at a path the read just reported ENOENT for, so
    // whatever occupied it has already been replaced — same remedy as an
    // outright removal, and the same message.
    return { kind: 'gone' };
  } catch (err) {
    // ENOENT is the removal itself, not a failure to look: the caller found the
    // path occupied and by now it is not. Only a lookup that failed for some
    // OTHER reason is genuinely unknown, and that error is the one fact worth
    // carrying — folding it into 'gone' is what sent operators after a file
    // that was never missing.
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { kind: 'gone' };
    return { kind: 'unknown', cause: err };
  }
}

/**
 * Raised when a creation-exclusive publish lost the race but the winner cannot
 * be read back afterwards. It lives beside createOwnerOnlyFileSync rather than
 * in either key's module because BOTH machine-local keys — the exception
 * fingerprint key and the vault keyring — publish their first copy through that
 * one primitive, and so fail through one type.
 *
 * It carries a `code` because the surfaces that render key failures branch on
 * one: a codeless error is treated as a CORRUPT key file, whose remedy is
 * deleting it. Doing that here would destroy everything written under the
 * perfectly good key the winner had just published — every exception grant on
 * the machine, or every pointer sealed under a vault epoch.
 */
export class KeyUnclaimableError extends Error {
  readonly code = 'key-unclaimable';
  // `cause` is installed only when there IS one. Passing { cause: undefined }
  // defines the property anyway, so an error carrying nothing would still answer
  // `'cause' in err` — a present-but-empty field reads as a diagnosis that was
  // captured and then lost, which is worse than its plain absence.
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'KeyUnclaimableError';
  }
}

/**
 * Owner-only CREATE of `file`: publish it only if nothing is there already.
 * Returns false when something already occupies the path — the caller adopts
 * what is there rather than replacing it. The caller must have created the
 * parent dir (ensureDataDirSync).
 *
 * true and false are not the only outcomes. Anything that is neither "won" nor
 * "occupied" THROWS, and throws the RAW errno — never KeyUnclaimableError, which
 * this function does not raise. A directory sitting at the tmp path is the
 * reachable example: the `wx` create fails EEXIST and that EEXIST propagates as
 * a plain Error, even though the FINAL path was free. So a caller reading only
 * the boolean cannot tell "someone else holds it" from "this store is broken";
 * distinguishing those means catching.
 *
 * This is the exclusive twin of writeOwnerOnlyFileSync, and it exists because
 * neither of the two obvious primitives has both properties a first-time
 * publisher needs:
 *
 *   - `rename` is atomic but REPLACES, so two writers each publish their own
 *     content and the last one wins.
 *   - `open(O_CREAT|O_EXCL)` at the final path picks one winner, but publishes
 *     an EMPTY inode and fills it on the next syscall. A concurrent reader — in
 *     particular the loser, re-reading in order to adopt — can read zero bytes
 *     and mistake a live file for a corrupt one. It also leaves that empty file
 *     behind for good if the write never lands.
 *
 * `link` has both: it publishes a name for an inode that is ALREADY complete,
 * and it fails EEXIST rather than replacing. So a reader sees the file absent or
 * whole, and exactly one caller wins.
 *
 * The tmp is per-thread and removed in a `finally`, so a failed or interrupted
 * write leaves nothing behind. On the `link` path it also leaves no half-made
 * file at the FINAL path, because the only thing that ever appears there is a
 * name for an inode that is already complete. The tmp create uses `wx`, which
 * refuses to follow a symlink; `link` refuses an occupied final path whether it
 * holds a file or a symlink.
 *
 * Hard links are unavailable on a few filesystems (FAT/exFAT, some network and
 * FUSE mounts). There the publish falls back to an exclusive open at the final
 * path, which keeps the one-winner guarantee but gives up BOTH of the properties
 * the paragraph above states: a concurrent reader can see the file at zero
 * length, and an interrupted write strands a TRUNCATED file at the final name —
 * the corrupt-file state whose documented remedy is deleting it. Neither is
 * avoidable while still publishing on a filesystem that cannot hard-link, so the
 * fallback is the weaker guarantee taken deliberately, not an oversight.
 *
 * Which of the two routes ran is not observable from the return value, and does
 * not need to be: an occupied final path answers false either way, because the
 * fallback's `wx` create reports EEXIST there exactly as `link` does. Only the
 * two properties above are given up on that path — never the one-winner answer.
 */
export function createOwnerOnlyFileSync(file: string, data: string): boolean {
  // Per THREAD, not just per process. A worker thread shares its parent's pid,
  // so a pid-only name makes two concurrent callers collide on the tmp — one
  // fails to create it, and the other has its in-flight tmp deleted underneath
  // it by the loser's cleanup. Still deterministic, so a same-thread tmp left
  // by an earlier crash is reclaimed rather than accumulating.
  const tmp = `${file}.${String(process.pid)}.${String(threadId)}.new`;
  try {
    rmSync(tmp, { force: true });
  } catch {
    // best-effort: unlink removes a leftover/symlinked tmp without touching its
    // target; the exclusive `wx` create below still refuses to follow a symlink.
  }
  let created: boolean;
  try {
    writeExclusiveOwnerOnlySync(tmp, data);
    created = publishByLink(tmp, file, data);
  } finally {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // best-effort cleanup — never mask the original write/link error.
    }
  }
  if (created) tightenFile(file);
  return created;
}

// Errno codes meaning "this filesystem cannot hard-link at all", as opposed to
// "this particular link failed". There is no single canonical one — Linux vfat
// reports EPERM, macOS on exFAT and several FUSE/SMB mounts report ENOTSUP (or
// the EOPNOTSUPP spelling, a distinct errno there), and Windows on FAT32
// surfaces EINVAL.
//
// This set is a JUDGEMENT CALL rather than a derivation: it is the codes seen in
// practice, and it is not exhaustive. Getting it wrong is not cosmetic — a code
// missing here makes createOwnerOnlyFileSync throw on a filesystem where the
// tmp+rename write it replaced would have succeeded, so the key cannot be minted
// at all. An uncovered code belongs in this set, not worked around at a caller.
//
// EXDEV and EMLINK are deliberately ABSENT despite naming link failures: the tmp
// is a sibling of the final path, so there is no cross-device case, and the link
// count goes 1 -> 2, so LINK_MAX is unreachable. Either arriving here would mean
// a bug in this function, and throwing is the right answer to that.
const LINK_UNSUPPORTED = new Set(['EPERM', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP', 'EINVAL']);

// Link `tmp` into place, or say the path was taken. EEXIST is the answer this
// is asking for, not a failure. Where the filesystem cannot hard-link at all —
// and only there — fall back to creating the final path exclusively and writing
// it in place.
function publishByLink(tmp: string, file: string, data: string): boolean {
  try {
    linkSync(tmp, file);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EEXIST') return false;
    if (!LINK_UNSUPPORTED.has(code ?? '')) throw err;
  }
  try {
    writeExclusiveOwnerOnlySync(file, data);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  }
}
