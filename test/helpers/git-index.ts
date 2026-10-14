import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// A git index as git writes it: the header, one entry per path in the given
// version's encoding, and a trailing checksum this reader does not verify.
export function encodeIndex(paths: string[], version: 2 | 3 | 4 = 2, extended = false): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('DIRC', 0, 'ascii');
  header.writeUInt32BE(version, 4);
  header.writeUInt32BE(paths.length, 8);
  parts.push(header);
  let previous = '';
  for (const path of [...paths].sort()) {
    const name = Buffer.from(path, 'utf8');
    const fixed = Buffer.alloc(extended ? 64 : 62);
    fixed.writeUInt32BE(0o100644, 24);
    const flags = Math.min(name.length, 0xfff) | (extended ? 0x4000 : 0);
    fixed.writeUInt16BE(flags, 60);
    parts.push(fixed);
    if (version === 4) {
      let common = 0;
      while (common < previous.length && previous[common] === path[common]) common++;
      const strip = previous.length - common;
      parts.push(Buffer.from([strip]), Buffer.from(path.slice(common), 'utf8'), Buffer.from([0]));
      previous = path;
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
