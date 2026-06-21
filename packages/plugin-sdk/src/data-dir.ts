import { chmodSync, mkdirSync, renameSync } from 'node:fs';
import { chmod, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

// All adapters share one on-disk home under the machine-account: settings and
// the local SQLite store. This is the BASE; the layout below splits it into
// settings/ and data/ subdirs so a new plugin reuses the exact same paths.
export function defaultDataDir(): string {
  return join(homedir(), '.aka');
}

// ~/.aka holds sensitive data (prompt content, policy, bearer token), so the
// directory is owner-only and files are written 0600. On multi-user systems
// this keeps other local users from reading the store, cache, or token.
export const DATA_DIR_MODE = 0o700;
export const DATA_FILE_MODE = 0o600;

// On-disk layout (shared by ALL plugins; see HLD B1):
//   ~/.aka/settings/  config.json (enterprise; Phase 2) · settings.json
//   ~/.aka/data/      aka.db (+ -wal/-shm sidecars) · policy-cache.json
export function settingsDir(base: string = defaultDataDir()): string {
  return join(base, 'settings');
}

export function dataDir(base: string = defaultDataDir()): string {
  return join(base, 'data');
}

export function dbPath(base: string = defaultDataDir()): string {
  return join(dataDir(base), 'aka.db');
}

// Create the dir owner-only, and tighten it even if it pre-existed with looser
// permissions. chmod is best-effort (a no-op on platforms without POSIX modes,
// e.g. Windows) and must never break the fail-open hook path.
export async function ensureDataDir(dir: string = defaultDataDir()): Promise<void> {
  await mkdir(dir, { recursive: true, mode: DATA_DIR_MODE });
  try {
    await chmod(dir, DATA_DIR_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
}

// Synchronous twin of ensureDataDir for the local-store open path: node:sqlite's
// DatabaseSync is synchronous, so the dir must exist before opening without an
// await. Same owner-only + best-effort-chmod contract.
export function ensureDataDirSync(dir: string = defaultDataDir()): void {
  mkdirSync(dir, { recursive: true, mode: DATA_DIR_MODE });
  try {
    chmodSync(dir, DATA_DIR_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
}

// One-time, best-effort relocation of the pre-layout flat files into their
// layout subdirs. Older installs wrote ~/.aka/config.json and
// ~/.aka/policy-cache.json directly under the base; the layout splits them by
// kind — config.json is settings, but policy-cache.json is a cache that lives
// with the SQLite store under data/ (where createPolicyStore reads it). Routing
// it to settings/ would strand the cache. Fail-open: any error (already moved,
// missing, unwritable) leaves the old file where it is — the loaders treat a
// missing settings/cache file as "unonboarded defaults" regardless.
export function migrateLegacyLayout(base: string = defaultDataDir()): void {
  const moves: { name: string; dest: string }[] = [
    { name: 'config.json', dest: settingsDir(base) },
    { name: 'policy-cache.json', dest: dataDir(base) },
  ];
  for (const { name, dest } of moves) {
    try {
      mkdirSync(dest, { recursive: true, mode: DATA_DIR_MODE });
      // mkdirSync only applies mode on creation (and is umask-masked); tighten
      // a pre-existing dir to owner-only too, since it holds sensitive files.
      try {
        chmodSync(dest, DATA_DIR_MODE);
      } catch {
        // best-effort: platform without POSIX modes, or not owned by us
      }
      renameSync(join(base, name), join(dest, name));
    } catch {
      // can't create dest, not present, already moved, or unwritable — skip
    }
  }
}
