import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';

/**
 * The text of the regular file at `path`. Throws what `openSync` throws for a missing path, and
 * throws for anything other than a regular file, or for one larger than `maxBytes` when given. The
 * check and the read use one descriptor, so they see the same file. `O_NONBLOCK` keeps the open
 * itself from waiting on a pipe; it is undefined on Windows, where `|` treats it as 0.
 */
export function readRegularFile(path: string, maxBytes?: number): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(`not a regular file: ${path}`);
    if (maxBytes !== undefined && stat.size > maxBytes) throw new Error(`file too large: ${path}`);
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}
