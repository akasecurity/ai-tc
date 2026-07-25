import { renameSync } from 'node:fs';
import { chmod, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { akaWarn } from './internal/warn.ts';
import { DATA_DIR_MODE, ensureDataDirSync as ensureDirOwnerOnly, tightenFile } from './paths.ts';

// The ~/.aka on-disk LAYOUT (which paths live where), shared by every local
// consumer — the plugin SDK, the CLI, and the OSS web-ui. It lives here (the
// lowest layer that touches the store) so all of them resolve identical paths
// without depending on the plugin SDK; the SDK re-exports these for back-compat.

// All adapters share one on-disk home under the machine-account: settings and
// the local SQLite store. This is the BASE; the layout below splits it into
// settings/ and data/ subdirs so a new plugin reuses the exact same paths.
export function defaultDataDir(): string {
  return join(homedir(), '.aka');
}

// On-disk layout (shared by ALL plugins):
//   ~/.aka/settings/  settings.json
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
  } catch (err) {
    // Fail-open, mirroring chmodBestEffort in paths.ts: swallow an absent target
    // and platforms without POSIX modes (Windows); surface anything else, since
    // a genuine failure means the dir's only at-rest control did not apply.
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
    if (process.platform === 'win32') return;
    akaWarn(`could not set owner-only permissions on ${dir}: ${String(err)}`);
  }
}

// Synchronous twin of ensureDataDir, defaulted to the layout base. Delegates to
// the single owner-only-mkdir implementation in paths.ts so the permission
// contract lives in exactly one place.
export function ensureLayoutDirSync(dir: string = defaultDataDir()): void {
  ensureDirOwnerOnly(dir);
}

// One-time, best-effort relocation of the pre-layout flat files into their
// layout subdirs. Older installs wrote ~/.aka/config.json and
// ~/.aka/policy-cache.json directly under the base; the layout splits them by
// kind — config.json is settings, but policy-cache.json is a cache that lives
// with the SQLite store under data/. Routing
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
      // Ensure + tighten the destination dir (it holds sensitive files), then
      // move the flat file in and hold it to 0600 too: rename preserves the
      // source's (possibly loose) mode, and a legacy config.json can carry a
      // token.
      ensureDirOwnerOnly(dest);
      const moved = join(dest, name);
      renameSync(join(base, name), moved);
      tightenFile(moved);
    } catch {
      // can't create dest, not present, already moved, or unwritable — skip
    }
  }
}
