import { chmodSync, mkdirSync } from 'node:fs';

// The shared SQLite store holds prompt/file content and masked findings, so the
// directory is owner-only and the DB files are written 0600. These mirror the
// modes the plugin SDK applies to ~/.aka; persistence owns its own copy so it
// never depends on the SDK's layout module.
export const DATA_DIR_MODE = 0o700;
export const DATA_FILE_MODE = 0o600;

// The single SQLite database file every plugin shares, under the caller-supplied
// data dir (e.g. ~/.aka/data computed by the SDK).
export const DB_FILENAME = 'aka.db';

// Create the data dir owner-only, tightening it even if it pre-existed with
// looser permissions. chmod is best-effort (a no-op on platforms without POSIX
// modes, e.g. Windows) and must never break the fail-open open path.
export function ensureDataDirSync(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
  try {
    chmodSync(dir, DATA_DIR_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
}

// 0600 on the DB and its WAL sidecars — they hold prompt/file content and masked
// findings. Best-effort: a no-op where POSIX modes don't apply, and the sidecars
// may not exist yet.
export function tightenPerms(file: string): void {
  for (const path of [file, `${file}-wal`, `${file}-shm`]) {
    try {
      chmodSync(path, DATA_FILE_MODE);
    } catch {
      // sidecar may not exist yet, or platform without POSIX modes
    }
  }
}
