import { chmod, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

// All adapters share one on-disk home: config, policy cache, event queue.
export function defaultDataDir(): string {
  return join(homedir(), '.aka');
}

// ~/.aka holds sensitive data (prompt content, policy, bearer token), so the
// directory is owner-only and files are written 0600. On multi-user systems
// this keeps other local users from reading the queue, cache, or token.
export const DATA_DIR_MODE = 0o700;
export const DATA_FILE_MODE = 0o600;

// Create the data dir owner-only, and tighten it even if it pre-existed with
// looser permissions. chmod is best-effort (a no-op on platforms without POSIX
// modes, e.g. Windows) and must never break the fail-open hook path.
export async function ensureDataDir(dir: string = defaultDataDir()): Promise<void> {
  await mkdir(dir, { recursive: true, mode: DATA_DIR_MODE });
  try {
    await chmod(dir, DATA_DIR_MODE);
  } catch {
    // best-effort: platform without POSIX modes, or not owned by us
  }
}
