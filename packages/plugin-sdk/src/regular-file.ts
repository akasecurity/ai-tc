import { readFileSync, statSync } from 'node:fs';

/**
 * The text of the regular file at `path`. Throws what `statSync` throws for a missing path, and
 * throws for anything other than a regular file, or for one larger than `maxBytes` when given. A
 * synchronous read of a pipe or a device can block the caller indefinitely.
 */
export function readRegularFile(path: string, maxBytes?: number): string {
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error(`not a regular file: ${path}`);
  if (maxBytes !== undefined && stat.size > maxBytes) throw new Error(`file too large: ${path}`);
  return readFileSync(path, 'utf8');
}
