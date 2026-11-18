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

/** The end of a file, and whether anything before it was left unread. */
export interface FileTail {
  text: string;
  /** True when the file is larger than the bytes read, so `text` starts mid-line. */
  truncated: boolean;
}

/**
 * The last `maxBytes` of the regular file at `path`, or the whole file when it is no larger.
 * Throws as `readRegularFile` does. Reads until those bytes are all in, so a short read never
 * drops the newest end.
 */
export function readRegularFileTail(path: string, maxBytes: number): FileTail {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error(notRegularFile(path));
    const length = Math.min(stat.size, maxBytes);
    const start = stat.size - length;
    const buffer = Buffer.alloc(length);
    let filled = 0;
    while (filled < length) {
      const read = readSync(fd, buffer, filled, length - filled, start + filled);
      if (read === 0) break;
      filled += read;
    }
    return { text: buffer.subarray(0, filled).toString('utf8'), truncated: start > 0 };
  } finally {
    closeSync(fd);
  }
}
