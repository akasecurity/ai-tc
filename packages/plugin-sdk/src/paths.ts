import { sep } from 'node:path';

/** Normalize a filesystem path to posix-style forward slashes. A no-op outside win32. */
export function toPosix(path: string): string {
  return path.split(sep).join('/');
}
