import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';

export function notRegularFile(path: string): string {
  return `not a regular file: ${path}`;
}

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
    if (!stat.isFile()) throw new Error(notRegularFile(path));
    if (maxBytes !== undefined && stat.size > maxBytes) throw new Error(`file too large: ${path}`);
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

/**
 * The last `maxBytes` of the regular file at `path`, or the whole file when it is smaller. Throws
 * as `readRegularFile` does. The text starts mid-line when the file is larger, so a caller reading
 * lines drops the first one.
 */
export function readRegularFileTail(path: string, maxBytes: number): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(notRegularFile(path));
    const length = Math.min(stat.size, maxBytes);
    const buffer = Buffer.alloc(length);
    const read = readSync(fd, buffer, 0, length, stat.size - length);
    return buffer.subarray(0, read).toString('utf8');
  } finally {
    closeSync(fd);
  }
}
