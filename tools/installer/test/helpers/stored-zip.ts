/**
 * A minimal STORED (uncompressed) zip writer, so building a win32 fixture
 * archive off Windows needs no PowerShell.
 *
 * WHY THIS EXISTS AT ALL, given `Compress-Archive` already did it. On Linux CI
 * runners `pwsh` intermittently dies before its command runs, with
 * `Unhandled exception.`, a `System.IO.FileLoadException` "The given assembly
 * name was invalid", and SIGABRT. It does not depend on the command: the
 * `Compress-Archive` child and `install.ps1` children alike have died with
 * that trace.
 *
 * What carries it is the .NET multicore-JIT startup profile pwsh keeps at
 * `$XDG_CACHE_HOME/powershell/StartupProfileData-NonInteractive` — under
 * `~/.cache` when the variable is unset — which every start reads and rewrites
 * on exit. Measured against pwsh 7.6.5 on Linux: a profile with one assembly
 * name damaged inside records that still parse reproduces the crash frame for
 * frame, while a truncated or spliced profile does not crash at all, because
 * .NET rejects a structurally broken file. The start that crashed leaves the
 * file byte-identical, so a retry reads the same damage — which is why
 * `compressArchive`'s retry burned all three attempts on a correct command, and
 * why neither a bigger budget nor a pause would help. A private
 * `XDG_CACHE_HOME` takes the file off the path.
 *
 * How a profile comes to be damaged is NOT measured. Concurrent starts sharing
 * the file are the origin reported upstream (PowerShell/PowerShell#26528), and
 * this suite does start pwsh concurrently, but that race has not been
 * reproduced.
 *
 * Off Windows this file builds the zip in Node, so a fixture build starts no
 * pwsh: nothing there reads a profile or adds a start to the ones sharing it.
 * The PowerShell children that remain off Windows — the probe and each
 * `install.ps1` attempt — run under `privateCacheHome` in run-installer.ts. The
 * `Compress-Archive` child does not. Off Windows it is reached only when a
 * caller passes one of `writeArchive`'s seams, and passing `exe` without `run`
 * would start a real pwsh reading the shared profile. Every caller passing a
 * seam today also passes `run`, so none does — a convention the signature does
 * not enforce.
 *
 * IT IS DELIBERATELY NOT USED ON WINDOWS. There the cmdlet is what
 * `archive-sea.mjs` runs to build a real release, the fixture mirrors it on
 * purpose, and it is the one host where the archive is EXPANDED again
 * (`install.ps1` step 5) rather than only hashed. Nothing observed has ever
 * aborted there. Off Windows the mirror buys nothing — no release is built on
 * those hosts, and no case gets past step 4 to open the archive.
 *
 * STORED, never deflated, for the same reason `compressArchive` passes
 * `-CompressionLevel NoCompression`: the installer hashes the archive and
 * expands it, and neither step cares whether the entries were compressed. It
 * also keeps this file short enough to read in one sitting, which a fixture
 * builder has to be.
 *
 * SCOPE, so nobody reaches for it where it would be wrong. Entries are held in
 * memory one at a time; sizes are the classic 32-bit fields with no zip64
 * fallback; and entry names are written as UTF-8 with the UTF-8 flag CLEAR,
 * which a reader is entitled to decode as CP437 — so a name outside ASCII would
 * round-trip wrong, and nothing here stops one being passed. All three are fine
 * for what this packs — off Windows a fixture root is a line of text and an
 * inert placeholder, because `writeWindowsPayload` only copies the real ~115 MB
 * PE when the host IS Windows, and the names are `aka-<triple>/`, `payload.txt`
 * and `aka.exe` — and none of them would be fine for a real release archive.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { crc32 } from 'node:zlib';

/**
 * A fixed 1980-01-01 00:00:00 in DOS date/time, so the same tree always yields
 * the same bytes.
 *
 * The tampering case builds one archive twice under one name and asserts the
 * installer refuses the second, which rests on the CONTENT changing the bytes.
 * A wall-clock stamp would change them on its own and let that case pass
 * without the content ever differing. 1980 rather than 0 because a zero DATE is
 * not a representable DOS date — the epoch of the format is 1980.
 */
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1;

/** FILE_ATTRIBUTE_DIRECTORY, in the DOS attribute byte — the LOW half of `external file attributes`. */
const DIR_ATTRS = 0x10;

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIR = 0x06054b50;

/** Zip 2.0 — the version that stored and deflated entries need. */
const VERSION = 20;

interface Entry {
  /** The path as it appears IN the archive, `/`-separated, `/`-suffixed for a directory. */
  readonly name: string;
  readonly data: Buffer;
  readonly isDirectory: boolean;
}

/** How a directory is listed. Injectable — see the parameter on `writeStoredZip`. */
export type DirLister = (dir: string) => string[];

/** Every file and directory under `dir`, depth first, named relative to `prefix`. */
function collect(dir: string, prefix: string, list: DirLister): Entry[] {
  const out: Entry[] = [];
  // Sorted, so the archive does not depend on the order the filesystem happens
  // to hand back — the same determinism argument as the fixed timestamp.
  for (const name of list(dir).sort()) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push({ name: `${prefix}${name}/`, data: Buffer.alloc(0), isDirectory: true });
      out.push(...collect(full, `${prefix}${name}/`, list));
      continue;
    }
    out.push({ name: `${prefix}${name}`, data: readFileSync(full), isDirectory: false });
  }
  return out;
}

/**
 * Write `<stage>/<rootName>` into `archivePath` as a stored zip, rooted at
 * `rootName/` exactly as `Compress-Archive -Path <dir>` roots it — which is
 * what `build-binaries.yml` asserts of a real archive and what `install.ps1`
 * joins onto to find the binary.
 */
export function writeStoredZip(
  archivePath: string,
  stage: string,
  rootName: string,
  // A seam, for the same reason the timestamp is fixed: the sort above is a
  // DETERMINISM claim, and a claim nothing can falsify is not one. Removing the
  // sort leaves every observation-based assertion green, because a host's own
  // readdir order is usually sorted already — so the only way to pin it is to
  // hand this an order that is deliberately not.
  list: DirLister = readdirSync,
): void {
  const entries = [
    { name: `${rootName}/`, data: Buffer.alloc(0), isDirectory: true },
    ...collect(join(stage, rootName), `${rootName}/`, list),
  ];

  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    // `crc32` returns an unsigned 32-bit number already; a stored entry's
    // compressed and uncompressed sizes are the same by definition.
    const crc = crc32(entry.data);
    const size = entry.data.length;

    const header = Buffer.alloc(30);
    header.writeUInt32LE(LOCAL_HEADER, 0);
    header.writeUInt16LE(VERSION, 4);
    header.writeUInt16LE(0, 6); // flags: none — bit 11 (UTF-8 names) clear, see SCOPE above
    header.writeUInt16LE(0, 8); // method: stored
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(size, 18);
    header.writeUInt32LE(size, 22);
    header.writeUInt16LE(name.length, 26);
    header.writeUInt16LE(0, 28); // extra field length
    local.push(header, name, entry.data);

    const record = Buffer.alloc(46);
    record.writeUInt32LE(CENTRAL_HEADER, 0);
    record.writeUInt16LE(VERSION, 4); // version made by
    record.writeUInt16LE(VERSION, 6); // version needed
    record.writeUInt16LE(0, 8);
    record.writeUInt16LE(0, 10);
    record.writeUInt16LE(DOS_TIME, 12);
    record.writeUInt16LE(DOS_DATE, 14);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(size, 20);
    record.writeUInt32LE(size, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt16LE(0, 30); // extra field length
    record.writeUInt16LE(0, 32); // comment length
    record.writeUInt16LE(0, 34); // disk number start
    record.writeUInt16LE(0, 36); // internal attributes
    record.writeUInt32LE(entry.isDirectory ? DIR_ATTRS : 0, 38);
    record.writeUInt32LE(offset, 42);
    central.push(record, name);

    offset += header.length + name.length + size;
  }

  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_OF_CENTRAL_DIR, 0);
  end.writeUInt16LE(0, 4); // this disk
  end.writeUInt16LE(0, 6); // disk the central directory starts on
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20); // comment length

  writeFileSync(archivePath, Buffer.concat([...local, directory, end]));
}
