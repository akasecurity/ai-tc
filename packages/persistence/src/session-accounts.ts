import { lstatSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

// Per-session account state under the data dir: for each coding-agent session,
// an append-only log of what its hooks saw of the login it runs under, and a
// cache of how far its transcript has been read, each named by the session's
// id. Every piece carries the binding hash of the attachment it was written
// under, and the whole directory is cleared when that attachment changes or
// ends. A file not written for thirty days is pruned.

/** The directory's name under the data dir. */
export const SESSION_ACCOUNTS_DIRNAME = 'session-accounts';

/** The directory itself. */
export function sessionAccountsDir(dataDir: string): string {
  return join(dataDir, SESSION_ACCOUNTS_DIRNAME);
}

/**
 * Remove the directory and everything in it. A symbolic link in its place is
 * removed, never followed. A directory that was never made is not an error.
 * Returns whether nothing remains. Never throws.
 */
export function clearSessionAccountState(dataDir: string): boolean {
  try {
    rmSync(sessionAccountsDir(dataDir), { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}

// How long a session's account state is kept after it was last written.
const SESSION_ACCOUNT_STATE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Remove each regular file directly in the directory whose last write is more
 * than thirty days before `nowMs`. A directory, a symbolic link or anything else
 * in it is left as it is, and so is a file that cannot be read or removed. A
 * symbolic link in the directory's own place is not followed, and nothing is
 * removed through it. No directory is not an error. Never throws.
 */
export function pruneSessionAccountState(dataDir: string, nowMs: number): void {
  let names: string[];
  try {
    // lstat reports a link itself, never what it points at.
    if (!lstatSync(sessionAccountsDir(dataDir)).isDirectory()) return;
    names = readdirSync(sessionAccountsDir(dataDir));
  } catch {
    return;
  }
  for (const name of names) {
    try {
      const file = join(sessionAccountsDir(dataDir), name);
      const stat = lstatSync(file);
      if (stat.isFile() && nowMs - stat.mtimeMs > SESSION_ACCOUNT_STATE_MAX_AGE_MS) {
        rmSync(file, { force: true });
      }
    } catch {
      // Skipped: the rest of the directory is still pruned.
    }
  }
}
