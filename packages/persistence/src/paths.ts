import { chmodSync, lstatSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';

// The shared SQLite store holds prompt/file content and masked findings, so the
// directory is owner-only and the DB files are written 0600. These mirror the
// modes the plugin SDK applies to ~/.aka; persistence owns its own copy so it
// never depends on the SDK's layout module.
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
  mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
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
    writeFileSync(tmp, data, { mode: DATA_FILE_MODE, flag: 'wx' });
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
