import { chmodSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';

import { akaWarn } from './internal/warn.ts';

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

// Paths already warned about, so a chmod that keeps failing on a hot path — e.g.
// the base dir + settings.json touched on every plugin hook when ~/.aka lives on
// a filesystem that rejects chmod (some SMB/NFS/WSL mounts, a root-owned file) —
// surfaces ONCE per process instead of two stderr lines on every hook.
const warnedChmodPaths = new Set<string>();

// chmod `path` to `mode`, swallowing the two benign outcomes — the target does
// not exist yet (a not-yet-created -wal/-shm sidecar) and a platform without
// POSIX modes (Windows) — and surfacing anything else on the warn channel, but
// at most once per path. A chmod that fails for any other reason means the
// store's ONLY at-rest control did not apply, which must not vanish silently. It
// still fails open: the caller never throws, so a permission glitch can't break
// a session.
function chmodBestEffort(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    if (process.platform === 'win32') return;
    if (warnedChmodPaths.has(path)) return;
    warnedChmodPaths.add(path);
    akaWarn(`could not set owner-only permissions on ${path}: ${String(err)}`);
  }
}

// 0700 on a data directory. Best-effort (see chmodBestEffort) — the single place
// the dir-mode policy lives, so the sync and async dir paths can't diverge.
export function tightenDir(dir: string): void {
  chmodBestEffort(dir, DATA_DIR_MODE);
}

// Create the data dir owner-only, tightening it even if it pre-existed with
// looser permissions. chmod is best-effort (a no-op on platforms without POSIX
// modes, e.g. Windows) and must never break the fail-open open path.
export function ensureDataDirSync(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
  tightenDir(dir);
}

// The -wal/-shm sidecar files SQLite keeps next to a database file in WAL mode.
export function walSidecars(file: string): string[] {
  return [`${file}-wal`, `${file}-shm`];
}

// 0600 on a single file — the DB alone, the exception key, a settings file, or a
// store backup copy. Best-effort (see chmodBestEffort).
export function tightenFile(file: string): void {
  chmodBestEffort(file, DATA_FILE_MODE);
}

// 0600 on the DB and its WAL sidecars — they hold prompt/file content and masked
// findings. Best-effort: a no-op where POSIX modes don't apply, and the sidecars
// may not exist yet.
export function tightenPerms(file: string): void {
  for (const path of [file, ...walSidecars(file)]) chmodBestEffort(path, DATA_FILE_MODE);
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
// have its target chmod'd. The `mode` lands on creation; the rename publishes an
// owner-only inode; the trailing tighten re-asserts 0600 belt-and-suspenders.
export function writeOwnerOnlyFileSync(file: string, data: string): void {
  const tmp = `${file}.${String(process.pid)}.tmp`;
  try {
    rmSync(tmp, { force: true });
  } catch {
    // best-effort: unlink removes a leftover/symlinked tmp without touching its
    // target; the exclusive `wx` create below still refuses to follow a symlink.
  }
  writeFileSync(tmp, data, { mode: DATA_FILE_MODE, flag: 'wx' });
  renameSync(tmp, file);
  tightenFile(file);
}
