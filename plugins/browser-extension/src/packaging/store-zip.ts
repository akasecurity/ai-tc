/**
 * The Chrome Web Store upload archive: a deterministic zip whose entries sit at
 * the archive ROOT, plus the transform applied to the manifest that goes into
 * it.
 *
 * ROOT, not a directory. `Compress-Archive -Path <dir>` and
 * `tools/installer/test/helpers/stored-zip.ts` both root every entry under a
 * `<name>/` segment, which is what a binary archive wants and what the store
 * rejects: it reads `manifest.json` from the top level of the upload and
 * refuses a package that wraps it.
 *
 * DETERMINISTIC, so the same `dist/` always produces the same bytes. Two things
 * would otherwise vary with nothing about the extension changing: the order a
 * host's `readdir` happens to return, and a wall-clock timestamp. Both are
 * fixed here — the entry list is sorted, and every entry carries the DOS epoch
 * rather than the time of the run.
 *
 * SCOPE, so nobody reaches for this where it would be wrong. Entries are held
 * in memory one at a time; sizes are the classic 32-bit fields with no zip64
 * fallback; and entry names are written as UTF-8 with the UTF-8 flag CLEAR,
 * which a reader is entitled to decode as CP437 — so a name outside ASCII would
 * round-trip wrong, and nothing here stops one being passed. All three hold for
 * what this packs: a built MV3 extension is a handful of ASCII-named files
 * totalling well under a megabyte.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { crc32, deflateRawSync } from 'node:zlib';

/**
 * 1980-01-01 00:00:00 in DOS date/time, carried by every entry.
 *
 * The determinism claim is that the archive's bytes are a function of the tree
 * and nothing else. A wall-clock stamp would change them with the content held
 * fixed, which is that claim's negation. 1980 rather than 0 because a zero DATE
 * is not a representable DOS date — the epoch of the format is 1980.
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

const STORED = 0;
const DEFLATED = 8;

/** The highest integer a Chrome version part may carry. */
const MAX_VERSION_PART = 65535;

/** How a directory is listed. Injectable — see `ArchiveOptions.list`. */
export type DirLister = (dir: string) => string[];

/** The instant a write happened, in epoch milliseconds. Injectable — see `ArchiveOptions.now`. */
export type Clock = () => number;

export interface ArchiveOptions {
  /**
   * Entry bytes that replace what is on disk, keyed by the name the entry
   * carries IN the archive. A key naming no file under the packaged directory
   * is refused rather than ignored.
   */
  readonly overrides?: ReadonlyMap<string, Buffer>;
  /**
   * How each directory is listed. A seam, for the same reason the timestamp is
   * fixed: the sort is a DETERMINISM claim, and a host's own `readdir` order is
   * usually sorted already — so an observation of the real filesystem cannot
   * falsify it. The only way to pin it is to hand this an order that is
   * deliberately not sorted.
   */
  readonly list?: DirLister;
  /**
   * When the archive was written. It reaches `WrittenArchive.writtenAt` and
   * nothing else: no field of the archive is derived from it, which is what
   * makes two writes under different clocks byte-identical.
   */
  readonly now?: Clock;
}

export interface WrittenArchive {
  readonly path: string;
  /** Every entry name, in the order written. Directories carry a trailing `/`. */
  readonly entries: readonly string[];
  readonly byteLength: number;
  readonly writtenAt: number;
}

/**
 * Whether Chrome accepts `version` in a manifest: one to four dot-separated
 * integers, each 0 to 65535, no leading zero on a part, and not all zero. There
 * is no pre-release suffix — a `-rc.1` is a different field (`version_name`).
 */
export function isLegalChromeVersion(version: string): boolean {
  const parts = version.split('.');
  if (parts.length > 4) return false;
  if (!parts.every((part) => /^(0|[1-9][0-9]*)$/.test(part) && Number(part) <= MAX_VERSION_PART)) {
    return false;
  }
  return parts.some((part) => part !== '0');
}

/** The two manifest fields a package version decides. */
export interface ManifestVersionFields {
  readonly version: string;
  /** Present only when the package version carries a suffix `version` cannot hold. */
  readonly version_name?: string;
}

/**
 * The manifest version fields for a package version.
 *
 * A bare `X.Y.Z` sets `version` alone. A pre-release or build suffix cannot go
 * in `version`, so the numeric core goes there and the WHOLE package version
 * goes in `version_name` — the display-only field chrome://extensions shows in
 * its place.
 */
export function manifestVersionFields(packageVersion: string): ManifestVersionFields {
  const core = packageVersion.split(/[-+]/, 1)[0] ?? '';
  return core === packageVersion
    ? { version: core }
    : { version: core, version_name: packageVersion };
}

/**
 * Why this tree may not be packaged for a store, or `undefined` when it may.
 *
 * Two refusals, and each answers a hole a Chrome-legality check cannot see.
 *
 * A store archive is built from a BARE package version only. Chrome's `version`
 * carries no suffix, so every pre-release of one core collapses onto the same
 * `version` AND the same archive name: `0.10.0-beta.1`, `0.10.0-beta.2` and the
 * eventual `0.10.0` are all `0.10.0`, at most one of them could ever be
 * uploaded, and a store accepts no upload whose version is not greater than the
 * last. Refusing says so at pack time rather than at the second upload.
 *
 * And `dist/` must AGREE with package.json on both halves — the whole version
 * and the numeric core — the way cli/scripts/bundle-extension.mjs checks the
 * bundled copy. This module builds nothing, so a `dist/` left by an earlier
 * build is complete, deterministic and store-ready while carrying the OLD
 * version; nothing about the archive it produces looks wrong.
 *
 * `manifestVersionFields` decides what "bare" means here rather than a second
 * split, so the refusal and the build cannot disagree about which versions need
 * a `version_name`.
 */
export function storeArchiveRefusal(
  packageVersion: string,
  built: ManifestVersionFields,
): string | undefined {
  const wanted = manifestVersionFields(packageVersion);
  if (wanted.version_name !== undefined) {
    return (
      `package.json is at ${packageVersion}, which is not a bare version — a store archive is ` +
      `built from a bare X.Y.Z only. Chrome's \`version\` holds no suffix, so every ` +
      `pre-release of ${wanted.version} collapses to version ${wanted.version} and to one ` +
      `archive name, and only one of them could ever be uploaded`
    );
  }
  const builtWhole = built.version_name ?? built.version;
  if (builtWhole !== packageVersion || built.version !== wanted.version) {
    return (
      `dist/manifest.json is at ${builtWhole} (version field ${built.version}), package.json ` +
      `at ${packageVersion} — run \`pnpm build\` first`
    );
  }
  if (built.version_name !== undefined) {
    return (
      `dist/manifest.json carries version_name ${built.version_name} beside the bare package ` +
      `version ${packageVersion}, which is built with no version_name — run \`pnpm build\` first`
    );
  }
  return undefined;
}

/**
 * The manifest a build writes to dist/: the committed one with its version
 * fields replaced by what `packageVersion` decides. A `version_name` the source
 * happens to carry is dropped rather than kept beside a version it no longer
 * describes; every other field is preserved in place.
 */
export function builtManifest(
  source: Readonly<Record<string, unknown>>,
  packageVersion: string,
): Record<string, unknown> {
  const kept = Object.fromEntries(
    Object.entries(source).filter(([field]) => field !== 'version_name'),
  );
  return { ...kept, ...manifestVersionFields(packageVersion) };
}

/**
 * The manifest that goes INTO the archive: the built one without `key`, every
 * other field preserved in place.
 *
 * `key` pins the id of an unpacked build. A store item holds its own key pair
 * and assigns the id from that, so the field decides nothing in an uploaded
 * package and is dropped rather than shipped.
 */
export function packagedManifest(
  built: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return Object.fromEntries(Object.entries(built).filter(([field]) => field !== 'key'));
}

interface Entry {
  /** The path as it appears IN the archive, `/`-separated, `/`-suffixed for a directory. */
  readonly name: string;
  readonly data: Buffer;
  readonly isDirectory: boolean;
}

/** Every file and directory under `dir`, depth first, named relative to `prefix`. */
function collect(
  dir: string,
  prefix: string,
  list: DirLister,
  overrides: ReadonlyMap<string, Buffer>,
): Entry[] {
  const out: Entry[] = [];
  for (const name of [...list(dir)].sort()) {
    const full = join(dir, name);
    const archiveName = `${prefix}${name}`;
    if (statSync(full).isDirectory()) {
      out.push({ name: `${archiveName}/`, data: Buffer.alloc(0), isDirectory: true });
      out.push(...collect(full, `${archiveName}/`, list, overrides));
      continue;
    }
    out.push({
      name: archiveName,
      data: overrides.get(archiveName) ?? readFileSync(full),
      isDirectory: false,
    });
  }
  return out;
}

/**
 * Write every file under `dir` into `archivePath`, each entry named relative to
 * `dir` with no root prefix.
 */
export function writeExtensionZip(
  archivePath: string,
  dir: string,
  options: ArchiveOptions = {},
): WrittenArchive {
  const overrides = options.overrides ?? new Map<string, Buffer>();
  const list = options.list ?? readdirSync;
  const now = options.now ?? Date.now;

  const entries = collect(dir, '', list, overrides);

  // An override the walk never matched is a silent substitution that did not
  // happen — for the manifest that means uploading the on-disk one instead of
  // the packaged one, which is the whole point of the override.
  const named = new Set(entries.map((entry) => entry.name));
  for (const name of overrides.keys()) {
    if (!named.has(name)) {
      throw new Error(`store-zip: override "${name}" names no file under ${dir}`);
    }
  }

  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    // A directory entry carries no data, so there is nothing to compress; every
    // file is deflated. `crc32` returns an unsigned 32-bit number already, and
    // the CRC and the uncompressed size are of the RAW bytes either way.
    const method = entry.isDirectory ? STORED : DEFLATED;
    const payload = entry.isDirectory ? entry.data : deflateRawSync(entry.data, { level: 9 });
    const crc = crc32(entry.data);
    const size = entry.data.length;

    const header = Buffer.alloc(30);
    header.writeUInt32LE(LOCAL_HEADER, 0);
    header.writeUInt16LE(VERSION, 4);
    header.writeUInt16LE(0, 6); // flags: none — bit 11 (UTF-8 names) clear, see SCOPE above
    header.writeUInt16LE(method, 8);
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(payload.length, 18);
    header.writeUInt32LE(size, 22);
    header.writeUInt16LE(name.length, 26);
    header.writeUInt16LE(0, 28); // extra field length
    local.push(header, name, payload);

    const record = Buffer.alloc(46);
    record.writeUInt32LE(CENTRAL_HEADER, 0);
    record.writeUInt16LE(VERSION, 4); // version made by
    record.writeUInt16LE(VERSION, 6); // version needed
    record.writeUInt16LE(0, 8); // flags
    record.writeUInt16LE(method, 10);
    record.writeUInt16LE(DOS_TIME, 12);
    record.writeUInt16LE(DOS_DATE, 14);
    record.writeUInt32LE(crc, 16);
    record.writeUInt32LE(payload.length, 20);
    record.writeUInt32LE(size, 24);
    record.writeUInt16LE(name.length, 28);
    record.writeUInt16LE(0, 30); // extra field length
    record.writeUInt16LE(0, 32); // comment length
    record.writeUInt16LE(0, 34); // disk number start
    record.writeUInt16LE(0, 36); // internal attributes
    record.writeUInt32LE(entry.isDirectory ? DIR_ATTRS : 0, 38);
    record.writeUInt32LE(offset, 42);
    central.push(record, name);

    offset += header.length + name.length + payload.length;
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

  const bytes = Buffer.concat([...local, directory, end]);
  writeFileSync(archivePath, bytes);

  return {
    path: archivePath,
    entries: entries.map((entry) => entry.name),
    byteLength: bytes.length,
    writtenAt: now(),
  };
}
