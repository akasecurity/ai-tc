import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

function encodeVarint(value: number): Buffer {
  const bytes = [value & 0x7f];
  for (let rest = value >>> 7; rest > 0; rest >>>= 7) bytes.unshift(0x80 | (--rest & 0x7f));
  return Buffer.from(bytes);
}

// A git index as git writes it: the header, one entry per path in the given
// version's encoding, and a trailing checksum this reader does not verify.
export function encodeIndex(paths: string[], version: 2 | 3 | 4 = 2, extended = false): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('DIRC', 0, 'ascii');
  header.writeUInt32BE(version, 4);
  header.writeUInt32BE(paths.length, 8);
  parts.push(header);
  let previous = Buffer.alloc(0);
  const names = paths.map((path) => Buffer.from(path, 'utf8')).sort((a, b) => Buffer.compare(a, b));
  for (const name of names) {
    const fixed = Buffer.alloc(extended ? 64 : 62);
    fixed.writeUInt32BE(0o100644, 24);
    const flags = Math.min(name.length, 0xfff) | (extended ? 0x4000 : 0);
    fixed.writeUInt16BE(flags, 60);
    parts.push(fixed);
    if (version === 4) {
      // Git shares the prefix byte by byte, so a split can fall inside a
      // multi-byte character.
      let common = 0;
      while (common < previous.length && previous[common] === name[common]) common++;
      parts.push(encodeVarint(previous.length - common), name.subarray(common), Buffer.from([0]));
      previous = name;
    } else {
      const length = fixed.length + name.length;
      const padded = Math.ceil((length + 1) / 8) * 8;
      parts.push(name, Buffer.alloc(padded - length));
    }
  }
  parts.push(Buffer.alloc(20));
  return Buffer.concat(parts);
}

/** A repository at `root` whose index lists `tracked`. */
export function writeGitRepo(root: string, tracked: readonly string[]): void {
  mkdirSync(join(root, '.git'), { recursive: true });
  writeFileSync(join(root, '.git', 'index'), encodeIndex([...tracked]));
}
