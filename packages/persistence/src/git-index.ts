// Whether git tracks a file, read from the repository's index on disk: no
// child process, no network. Any index this reader cannot read in full answers
// "not tracked", so a file is never reported tracked unless the index lists it.
import { readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

const SIGNATURE = 'DIRC';
const HEADER_BYTES = 12;
const FIXED_ENTRY_BYTES = 62;
const EXTENDED_FLAG = 0x4000;

/** The variable-width integer a version 4 index prefixes each path with. */
function readVarint(buf: Buffer, start: number): { value: number; next: number } | undefined {
  let at = start;
  let byte = buf[at++];
  if (byte === undefined) return undefined;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[at++];
    if (byte === undefined) return undefined;
    value = ((value + 1) << 7) | (byte & 0x7f);
  }
  return { value, next: at };
}

/**
 * The paths a git index lists, relative to the working tree root with `/`
 * separators, or undefined for anything that is not a version 2, 3 or 4 index
 * this reader can walk to its last entry.
 */
export function parseGitIndex(buf: Buffer): Set<string> | undefined {
  if (buf.length < HEADER_BYTES || buf.toString('ascii', 0, 4) !== SIGNATURE) return undefined;
  const version = buf.readUInt32BE(4);
  if (version < 2 || version > 4) return undefined;
  const count = buf.readUInt32BE(8);
  const paths = new Set<string>();
  let at = HEADER_BYTES;
  let previous: Buffer = Buffer.alloc(0);
  for (let i = 0; i < count; i++) {
    if (at + FIXED_ENTRY_BYTES > buf.length) return undefined;
    const flags = buf.readUInt16BE(at + 60);
    const fixed =
      version >= 3 && (flags & EXTENDED_FLAG) !== 0 ? FIXED_ENTRY_BYTES + 2 : FIXED_ENTRY_BYTES;
    const nameStart = at + fixed;
    let name: Buffer;
    if (version === 4) {
      // The strip count is in bytes and can split a multi-byte character, so
      // the prefix stays raw bytes until the whole path is assembled.
      const strip = readVarint(buf, nameStart);
      if (strip === undefined || strip.value > previous.length) return undefined;
      const end = buf.indexOf(0, strip.next);
      if (end === -1) return undefined;
      name = Buffer.concat([
        previous.subarray(0, previous.length - strip.value),
        buf.subarray(strip.next, end),
      ]);
      at = end + 1;
    } else {
      const end = buf.indexOf(0, nameStart);
      if (end === -1) return undefined;
      name = buf.subarray(nameStart, end);
      at += (fixed + (end - nameStart) + 8) & ~7;
    }
    if (at > buf.length) return undefined;
    paths.add(name.toString('utf8'));
    previous = name;
  }
  return paths;
}

/** The index file of the repository whose `.git` entry is `dotGit`, or undefined. */
function indexFileOf(dotGit: string): string | undefined {
  const stat = statSync(dotGit, { throwIfNoEntry: false });
  if (stat === undefined) return undefined;
  if (stat.isDirectory()) return join(dotGit, 'index');
  const pointer = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, 'utf8'))?.[1];
  return pointer === undefined ? undefined : join(resolve(dirname(dotGit), pointer), 'index');
}

function readIndex(root: string): Set<string> | undefined {
  try {
    const file = indexFileOf(join(root, '.git'));
    return file === undefined ? undefined : parseGitIndex(readFileSync(file));
  } catch {
    return undefined;
  }
}

function within(parent: string, child: string): string | undefined {
  const rel = relative(parent, child);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return undefined;
  return rel;
}

/**
 * Whether git tracks a file: the nearest directory at or above it holding a
 * `.git` entry is the file's
 * repository, and the file is tracked when that repository's index lists it.
 * Each repository's index is read once, on first use. Never throws.
 */
export function createTrackedFileLookup(): (file: string) => boolean {
  const repositoryOf = new Map<string, string | null>();
  const indexes = new Map<string, Set<string> | undefined>();

  const repositoryFor = (dir: string): string | null => {
    const known = repositoryOf.get(dir);
    if (known !== undefined) return known;
    let found: string | null;
    if (statSync(join(dir, '.git'), { throwIfNoEntry: false }) !== undefined) found = dir;
    else if (dirname(dir) === dir) found = null;
    else found = repositoryFor(dirname(dir));
    repositoryOf.set(dir, found);
    return found;
  };

  return (file) => {
    try {
      const abs = resolve(file);
      const root = repositoryFor(dirname(abs));
      if (root === null) return false;
      if (!indexes.has(root)) indexes.set(root, readIndex(root));
      const rel = within(root, abs);
      return rel !== undefined && (indexes.get(root)?.has(rel.split(sep).join('/')) ?? false);
    } catch {
      return false;
    }
  };
}
