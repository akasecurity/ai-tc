import { renameSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

import {
  DATA_DIR_MODE,
  ensureDataDirSync as ensureDirOwnerOnly,
  tightenDir,
  tightenFile,
} from './paths.ts';

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

// On-disk layout (shared by ALL plugins). The sidecar set is the one dbSidecars
// creates and tightens — three, not two: -wal/-shm are the pair SQLite keeps in
// write-ahead logging, and -journal is what it writes instead wherever WAL is
// unavailable (a DrvFs `/mnt/c` path under WSL, some network mounts). data/ also
// accumulates `.bak` snapshot copies of the store and, after a snapshot cut
// short by a kill, a `.bak.partial` staging directory:
//   ~/.aka/settings/  settings.json
//   ~/.aka/data/      aka.db (+ -wal/-shm/-journal sidecars) · policy-cache.json
//                     · aka.db.<tag>.<millis>.<random>.bak (+ .partial staging)
//   ~/.aka/keys/      vault.key (see keysDir — deliberately its own directory)
export function settingsDir(base: string = defaultDataDir()): string {
  return join(base, 'settings');
}

export function dataDir(base: string = defaultDataDir()): string {
  return join(base, 'data');
}

export function dbPath(base: string = defaultDataDir()): string {
  return join(dataDir(base), 'aka.db');
}

// Key material lives in its own directory rather than beside the store, so a
// backup or sync tool can exclude ~/.aka/keys/ and carry the database without
// the means to decrypt it. That separation is the whole of what encryption at
// rest buys here: it defends a copied database, not a live process on this
// machine, which reads both by construction.
export function keysDir(base: string = defaultDataDir()): string {
  return join(base, 'keys');
}

// Create the dir owner-only, and tighten it even if it pre-existed with looser
// permissions. chmod is best-effort (a no-op on platforms without POSIX modes,
// e.g. Windows) and must never break the fail-open hook path.
export async function ensureDataDir(dir: string = defaultDataDir()): Promise<void> {
  await mkdir(dir, { recursive: true, mode: DATA_DIR_MODE });
  // Delegate the tighten to the one shared helper so the sync and async dir
  // paths can't drift on what a failed chmod means. `tightenDir` is silent by
  // design: it declines to chmod through a symlink and swallows every other
  // failure. Deciding whether that silence is worth surfacing belongs to the
  // callers that can actually address a user — `aka init` prints the full
  // symlink report, and the hooks warn once per session — not to this helper,
  // which runs on every hook fire and must never break one.
  tightenDir(dir);
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
  // These two names are LITERALS on purpose, and deliberately do not track
  // POLICY_CACHE_FILENAME. This table describes where older installs actually
  // wrote — a frozen historical fact — so binding it to a constant that can move
  // would make a rename silently stop relocating the file those installs left,
  // stranding it under the base for ever. A rename is a new name to ADD here,
  // not an edit to this row.
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
