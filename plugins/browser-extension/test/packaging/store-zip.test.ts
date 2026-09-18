import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

import { afterAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type {
  ArchiveOptions,
  DirLister,
  ManifestVersionFields,
  WrittenArchive,
} from '../../src/packaging/store-zip.ts';
import {
  builtManifest,
  isLegalChromeVersion,
  manifestVersionFields,
  packagedManifest,
  storeArchiveRefusal,
  writeExtensionZip,
} from '../../src/packaging/store-zip.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/packaging -> plugins/browser-extension
const PACKAGE_ROOT = join(HERE, '..', '..');
// globalSetup has run `pnpm build`, so this is present and current.
const DIST = join(PACKAGE_ROOT, 'dist');

// Spelled out here rather than imported from the module under test: an
// expectation that reads its own subject cannot catch the subject moving.
// 0x0000 is 00:00:00, and 0x0021 is ((1980 - 1980) << 9) | (1 << 5) | 1.
const DOS_TIME_1980 = 0x0000;
const DOS_DATE_1980 = 0x0021;

const STORED = 0;
const DEFLATED = 8;

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIR = 0x06054b50;

const outDir = mkdtempSync(join(tmpdir(), 'aka-store-zip-'));
afterAll(() => {
  removeTree(outDir);
});

interface ArchiveEntry {
  /** The name the entry carries IN the archive. A directory keeps its trailing `/`. */
  readonly name: string;
  readonly method: number;
  /** The general-purpose bit flag in the CENTRAL directory record. */
  readonly flags: number;
  readonly dosTime: number;
  readonly dosDate: number;
  /**
   * The stamp in this entry's own LOCAL header. Carried beside the central
   * directory's copy because they are independent fields written in separate
   * statements: stamping the local header of every entry but the first is
   * invisible both to a central-directory read and to a raw read of byte 10 of
   * the file, which is the first local header and nothing else.
   */
  readonly localTime: number;
  readonly localDate: number;
  /** The general-purpose bit flag in this entry's own LOCAL header. */
  readonly localFlags: number;
  readonly content: Buffer;
}

/**
 * The archive read back through its CENTRAL DIRECTORY, which is what a zip
 * reader (and the store) uses — walking the local headers front to back would
 * agree with a writer that emitted a broken directory.
 */
function readArchive(bytes: Buffer): ArchiveEntry[] {
  // Nothing here writes an archive comment, so the record is the last 22 bytes.
  const eocd = bytes.length - 22;
  expect(bytes.readUInt32LE(eocd)).toBe(END_OF_CENTRAL_DIR);

  const count = bytes.readUInt16LE(eocd + 10);
  // The entry count appears twice (this disk, then the total) and a reader may
  // use either; the directory's offset and size are what a reader seeks by.
  // Checked here so a writer that emits an inconsistent record is caught by
  // every case below rather than by whichever one happens to read that field.
  expect(bytes.readUInt16LE(eocd + 8)).toBe(count);
  expect(bytes.readUInt32LE(eocd + 16) + bytes.readUInt32LE(eocd + 12)).toBe(eocd);

  let at = bytes.readUInt32LE(eocd + 16);
  const out: ArchiveEntry[] = [];

  for (let i = 0; i < count; i += 1) {
    expect(bytes.readUInt32LE(at)).toBe(CENTRAL_HEADER);
    const method = bytes.readUInt16LE(at + 10);
    const compressedSize = bytes.readUInt32LE(at + 20);
    const nameLength = bytes.readUInt16LE(at + 28);
    const extraLength = bytes.readUInt16LE(at + 30);
    const commentLength = bytes.readUInt16LE(at + 32);
    const localAt = bytes.readUInt32LE(at + 42);

    expect(bytes.readUInt32LE(localAt)).toBe(LOCAL_HEADER);
    const dataAt =
      localAt + 30 + bytes.readUInt16LE(localAt + 26) + bytes.readUInt16LE(localAt + 28);
    const stored = bytes.subarray(dataAt, dataAt + compressedSize);

    out.push({
      name: bytes.subarray(at + 46, at + 46 + nameLength).toString('utf8'),
      method,
      flags: bytes.readUInt16LE(at + 8),
      dosTime: bytes.readUInt16LE(at + 12),
      dosDate: bytes.readUInt16LE(at + 14),
      localTime: bytes.readUInt16LE(localAt + 10),
      localDate: bytes.readUInt16LE(localAt + 12),
      localFlags: bytes.readUInt16LE(localAt + 6),
      content: method === DEFLATED ? inflateRawSync(stored) : Buffer.from(stored),
    });

    at += 46 + nameLength + extraLength + commentLength;
  }

  // The walk consumed exactly the directory the record declares, so a count or
  // a size that disagrees with the records themselves cannot go unread.
  expect(at).toBe(eocd);

  return out;
}

interface Written {
  readonly archive: WrittenArchive;
  readonly bytes: Buffer;
  readonly entries: ArchiveEntry[];
  readonly names: string[];
}

function writeArchive(name: string, options: ArchiveOptions = {}): Written {
  const archive = writeExtensionZip(join(outDir, name), DIST, options);
  const bytes = readFileSync(archive.path);
  const entries = readArchive(bytes);
  return { archive, bytes, entries, names: entries.map((entry) => entry.name) };
}

/** A digest rather than the buffers themselves, so a mismatch prints two lines. */
const digest = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

const manifestBytes = (manifest: Readonly<Record<string, unknown>>): Buffer =>
  Buffer.from(JSON.stringify(manifest, null, 2) + '\n');

const readJson = (...segments: string[]): Record<string, unknown> =>
  JSON.parse(readFileSync(join(...segments), 'utf8')) as Record<string, unknown>;

/**
 * A built manifest's version fields, in the shape `storeArchiveRefusal` takes.
 *
 * `version_name` is carried only when the manifest really holds a string, which
 * is the same distinction the field itself makes: absent means a bare version
 * built it, and an own key set to `undefined` is not the same thing.
 */
const builtVersionFields = (manifest: Readonly<Record<string, unknown>>): ManifestVersionFields => {
  const versionName = manifest.version_name;
  return {
    version: String(manifest.version),
    ...(typeof versionName === 'string' ? { version_name: versionName } : {}),
  };
};

describe('the store upload archive', () => {
  it('names every entry at the archive ROOT', () => {
    const { names } = writeArchive('root.zip');

    expect(names.length).toBeGreaterThan(0);
    expect(names).toContain('manifest.json');
    // The store reads manifest.json from the top level of the upload, so a
    // wrapper segment is a rejected package rather than a cosmetic difference.
    expect(names.filter((name) => name.endsWith('/manifest.json'))).toEqual([]);

    // Every name resolves under dist/ exactly as written. A root prefix — the
    // shape `Compress-Archive -Path <dir>` and tools/installer/test/helpers/
    // stored-zip.ts both produce — names nothing that exists, so it fails here.
    const unresolvable = names.filter((name) => !existsSync(join(DIST, name.replace(/\/$/, ''))));
    expect(unresolvable).toEqual([]);
  });

  it('carries every file the store needs to accept the package', () => {
    const { names } = writeArchive('complete.zip');

    // A package without the 128px icon is refused outright; one without
    // content.js installs and then does nothing at all.
    expect(names).toEqual(
      expect.arrayContaining([
        'manifest.json',
        'background.js',
        'content.js',
        'popup.js',
        'popup.html',
        'icons/icon16.png',
        'icons/icon48.png',
        'icons/icon128.png',
      ]),
    );
  });

  it('deflates its file entries and stores its directory entries', () => {
    const { entries } = writeArchive('methods.zip');
    const files = entries.filter((entry) => !entry.name.endsWith('/'));

    expect(files.length).toBeGreaterThan(0);
    expect(files.map((entry) => entry.method)).toEqual(files.map(() => DEFLATED));
    for (const entry of entries.filter((e) => e.name.endsWith('/'))) {
      expect({ name: entry.name, method: entry.method }).toEqual({
        name: entry.name,
        method: STORED,
      });
    }
  });

  it('round-trips each entry back to the bytes on disk', () => {
    const { entries } = writeArchive('round-trip.zip');
    const files = entries.filter((entry) => !entry.name.endsWith('/'));

    expect(files.length).toBeGreaterThan(0);
    for (const entry of files) {
      expect(digest(entry.content), entry.name).toBe(digest(readFileSync(join(DIST, entry.name))));
    }
  });

  it('stamps every entry with the fixed 1980 DOS date and time', () => {
    const { bytes, entries } = writeArchive('stamps.zip');

    expect(entries.length).toBeGreaterThan(0);
    // The first local header begins at byte 0 of the file: mtime at +10,
    // mdate at +12.
    expect(bytes.readUInt32LE(0)).toBe(LOCAL_HEADER);
    expect(bytes.readUInt16LE(10)).toBe(DOS_TIME_1980);
    expect(bytes.readUInt16LE(12)).toBe(DOS_DATE_1980);

    // And EVERY entry, in BOTH of its copies — the central record at +12 / +14
    // and that entry's own local header at +10 / +12. They are independent
    // fields written in separate statements, so a writer can stamp one of them,
    // or all but the first; the assertion above sees neither.
    for (const entry of entries) {
      expect({
        name: entry.name,
        dosTime: entry.dosTime,
        dosDate: entry.dosDate,
        localTime: entry.localTime,
        localDate: entry.localDate,
      }).toEqual({
        name: entry.name,
        dosTime: DOS_TIME_1980,
        dosDate: DOS_DATE_1980,
        localTime: DOS_TIME_1980,
        localDate: DOS_DATE_1980,
      });
    }
  });

  // Bit 11 set says the names are UTF-8; the writer keeps every flag clear (see
  // SCOPE in store-zip.ts). Both copies, because like the stamps above they are
  // written in separate statements and a writer can clear one and not the other.
  it('clears the general-purpose flags on every entry, in both header copies', () => {
    const { entries } = writeArchive('flags.zip');

    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect({ name: entry.name, flags: entry.flags, localFlags: entry.localFlags }).toEqual({
        name: entry.name,
        flags: 0,
        localFlags: 0,
      });
    }
  });

  it('writes the same bytes under clocks a day apart', () => {
    const day = 24 * 60 * 60 * 1000;
    const first = writeArchive('clock-first.zip', { now: () => day });
    const second = writeArchive('clock-second.zip', { now: () => day * 2 });

    // The injected clock IS the one in force. Without this the equality below
    // would hold just as well if the option were misspelled and ignored, which
    // is the one way this case could pass while the bytes were time-dependent.
    expect(first.archive.writtenAt).toBe(day);
    expect(second.archive.writtenAt).toBe(day * 2);

    expect(digest(second.bytes)).toBe(digest(first.bytes));
  });

  it('writes different bytes when a file changes', () => {
    // The control for the case above: byte equality there must be a property of
    // the tree, not of a writer that emits a constant.
    const built = readJson(DIST, 'manifest.json');
    const base = writeArchive('control-base.zip');
    const changed = writeArchive('control-changed.zip', {
      overrides: new Map([['manifest.json', manifestBytes({ ...built, description: 'changed' })]]),
    });

    expect(digest(changed.bytes)).not.toBe(digest(base.bytes));
  });

  it('writes the same bytes whatever order the lister returns', () => {
    const reversed: DirLister = (dir) => [...readdirSync(dir)].reverse();

    // A host's own readdir is usually sorted already, so this is the only thing
    // that can falsify the sort.
    expect(reversed(DIST)).not.toEqual(readdirSync(DIST));

    const sorted = writeArchive('order-sorted.zip');
    const shuffled = writeArchive('order-reversed.zip', { list: reversed });

    expect(shuffled.names).toEqual(sorted.names);
    expect(digest(shuffled.bytes)).toBe(digest(sorted.bytes));
  });

  it('refuses an override that names no file in the tree', () => {
    // An override the walk never matched is a substitution that did not happen:
    // for the manifest that means uploading the on-disk one, `key` and all.
    expect(() =>
      writeExtensionZip(join(outDir, 'refused.zip'), DIST, {
        overrides: new Map([['manifest.json.bak', manifestBytes({})]]),
      }),
    ).toThrow(/names no file/);
  });
});

describe('packagedManifest', () => {
  const source = readJson(PACKAGE_ROOT, 'manifest.json');

  it('drops key and preserves every other field in place', () => {
    // Asserted on the source first, so the case cannot pass because the
    // committed manifest stopped carrying a key at all.
    expect(Object.keys(source)).toContain('key');

    const packaged = packagedManifest(source);

    expect(Object.keys(packaged)).toEqual(Object.keys(source).filter((f) => f !== 'key'));
    expect(Object.keys(packaged).length).toBeGreaterThan(0);
    for (const field of Object.keys(packaged)) {
      expect(packaged[field], field).toEqual(source[field]);
    }
  });

  it('leaves the manifest inside the archive without a key', () => {
    const built = readJson(DIST, 'manifest.json');
    expect(Object.keys(built)).toContain('key');

    const { entries } = writeArchive('packaged.zip', {
      overrides: new Map([['manifest.json', manifestBytes(packagedManifest(built))]]),
    });
    const entry = entries.find((candidate) => candidate.name === 'manifest.json');
    if (entry === undefined) throw new Error('the archive carries no manifest.json entry');

    const inArchive = JSON.parse(entry.content.toString('utf8')) as Record<string, unknown>;
    expect(Object.keys(inArchive)).not.toContain('key');
    // The store reads the version out of THIS copy, so it has to survive the
    // transform — and be one Chrome accepts.
    expect(inArchive.version).toBe(built.version);
    expect(isLegalChromeVersion(String(inArchive.version))).toBe(true);
  });
});

describe('manifestVersionFields', () => {
  // The package version follows the CLI's, and the CLI's may carry a
  // pre-release suffix. The live package version only ever exercises one of the
  // two shapes, so both are driven here.
  it.each([
    ['0.9.11', '0.9.11', undefined],
    ['1.0.0', '1.0.0', undefined],
    ['0.10.0-beta.1', '0.10.0', '0.10.0-beta.1'],
    ['0.10.0-nightly.20260918.gabc1234', '0.10.0', '0.10.0-nightly.20260918.gabc1234'],
    ['0.9.0-rc1', '0.9.0', '0.9.0-rc1'],
    ['1.2.3+build.7', '1.2.3', '1.2.3+build.7'],
    ['1.2.3-beta.1+build.7', '1.2.3', '1.2.3-beta.1+build.7'],
  ])('%s -> version %s, version_name %s', (packageVersion, version, versionName) => {
    const fields = manifestVersionFields(packageVersion);

    expect(fields.version).toBe(version);
    expect(fields.version_name).toBe(versionName);
    // A bare version must not grow the key at all: `version_name: undefined`
    // would serialize away, but an own key is what a spread copies.
    expect(Object.keys(fields)).toEqual(
      versionName === undefined ? ['version'] : ['version', 'version_name'],
    );
    expect(isLegalChromeVersion(fields.version)).toBe(true);
    // Whichever shape, the whole package version is recoverable from the pair.
    expect(fields.version_name ?? fields.version).toBe(packageVersion);
  });
});

describe('builtManifest', () => {
  const source = readJson(PACKAGE_ROOT, 'manifest.json');

  it('replaces the version and keeps every other field in place', () => {
    const built = builtManifest(source, '0.9.11');

    expect(Object.keys(built)).toEqual(Object.keys(source));
    expect(built.version).toBe('0.9.11');
    const others = Object.keys(source).filter((field) => field !== 'version');
    expect(others.length).toBeGreaterThan(0);
    for (const field of others) {
      expect(built[field], field).toEqual(source[field]);
    }
  });

  it('splits a pre-release across version and version_name', () => {
    const built = builtManifest(source, '0.10.0-beta.1');

    expect(built.version).toBe('0.10.0');
    expect(built.version_name).toBe('0.10.0-beta.1');
    expect(isLegalChromeVersion(String(built.version))).toBe(true);
    // Appended after the fields the source carries, none of which moved.
    expect(Object.keys(built)).toEqual([...Object.keys(source), 'version_name']);
  });

  it('drops a version_name the source carries when the package version is bare', () => {
    const stale = { ...source, version_name: '0.1.0-beta.9' };

    const built = builtManifest(stale, '0.9.11');

    expect(Object.keys(built)).not.toContain('version_name');
    expect(built.version).toBe('0.9.11');
  });

  it('survives packaging: the archive copy keeps both fields', () => {
    const packaged = packagedManifest(builtManifest(source, '0.10.0-beta.1'));

    expect(packaged.version).toBe('0.10.0');
    expect(packaged.version_name).toBe('0.10.0-beta.1');
    expect(Object.keys(packaged)).not.toContain('key');
  });
});

describe('storeArchiveRefusal', () => {
  // Every row names the package version and the BUILT manifest's version fields,
  // because the two holes this closes are exactly a disagreement between them: a
  // suffixed package version (whose pre-releases all collapse onto one Chrome
  // `version` and one archive name) and a dist/ left by an earlier build.
  //
  // A row's expectation is a pattern rather than the whole sentence: the property
  // is WHICH refusal fired, and an equality against the prose would make rewording
  // the message a test failure. Non-emptiness is asserted separately below, so a
  // refusal that degraded to `''` cannot satisfy a pattern vacuously.
  it.each<[string, string, ManifestVersionFields, RegExp | undefined]>([
    ['bare and agreeing', '0.9.11', { version: '0.9.11' }, undefined],
    ['bare and agreeing, past 1.0.0', '1.2.3', { version: '1.2.3' }, undefined],
    [
      'suffixed package version',
      '0.10.0-beta.1',
      { version: '0.10.0', version_name: '0.10.0-beta.1' },
      /not a bare version/,
    ],
    [
      'build-metadata package version',
      '1.2.3+build.7',
      { version: '1.2.3', version_name: '1.2.3+build.7' },
      /not a bare version/,
    ],
    ['stale built version', '0.10.0', { version: '0.9.11' }, /run `pnpm build`/],
    [
      'built version_name present but the package version is bare',
      '0.9.11',
      { version: '0.9.11', version_name: '0.9.11' },
      /version_name/,
    ],
    [
      'core mismatch behind an agreeing whole version',
      '0.10.0',
      { version: '0.9.0', version_name: '0.10.0' },
      /version field 0\.9\.0/,
    ],
    // The likeliest stale dist/ there is, and the one only `version_name` can
    // see: the tree that built 0.10.0-beta.1 with the package now at the stable
    // 0.10.0. Chrome's `version` agrees on both sides, so the WHOLE version is
    // the only field that disagrees — collapse the two and a beta build packages
    // as its own stable.
    [
      'a pre-release build left behind by its own stable',
      '0.10.0',
      { version: '0.10.0', version_name: '0.10.0-beta.1' },
      /0\.10\.0-beta\.1/,
    ],
  ])('%s', (_label, packageVersion, built, pattern) => {
    const refusal = storeArchiveRefusal(packageVersion, built);

    if (pattern === undefined) {
      expect(refusal).toBeUndefined();
      return;
    }
    // Said before what it matches: every `toMatch` below is satisfied by a
    // message that carries the pattern and nothing a reader could act on, and an
    // `undefined` refusal would fail here rather than at the pattern.
    expect(refusal, 'the row expects a refusal and got none').toBeDefined();
    expect(String(refusal).length).toBeGreaterThan(0);
    expect(refusal).toMatch(pattern);
  });

  // Each refusal names BOTH versions, which is what makes the message actionable:
  // a reader has to see what dist/ holds and what was asked for.
  it('names both versions when dist disagrees', () => {
    const refusal = storeArchiveRefusal('0.10.0', { version: '0.9.11' });

    expect(refusal).toContain('0.9.11');
    expect(refusal).toContain('0.10.0');
  });

  // The live tree, which is what `pnpm package:zip` actually runs against. A
  // table of fixtures says the function decides correctly; this says the decision
  // it reaches HERE is "go ahead", so the refusals cannot be passing their table
  // while refusing every real build.
  it('accepts the built tree package:zip is pointed at', () => {
    const packageVersion = String(readJson(PACKAGE_ROOT, 'package.json').version);
    const built = readJson(DIST, 'manifest.json');

    expect(isLegalChromeVersion(String(built.version))).toBe(true);
    expect(storeArchiveRefusal(packageVersion, builtVersionFields(built))).toBeUndefined();
  });
});

// The table above says the DECISION is right. This says the SCRIPT acts on it,
// which is a separate claim and the one that was missing: demoting
// package-zip.mjs's `throw` to a log left every case above green while a
// complete `plugin-browser-extension-0.10.0-beta.1.zip` was written anyway.
// Measured, not supposed.
//
// Driven as a real subprocess over a standalone COPY of the package. The script
// derives its root from its own URL, so nothing short of moving it points it at
// another tree; and it needs no node_modules — `node:` builtins plus one
// type-stripped `.ts` import, which the Node 24 engines floor handles.
describe('package:zip acts on the refusal', () => {
  /**
   * A self-contained copy of the package with its versions edited.
   *
   * Under `outDir`, so the suite's own teardown removes it.
   */
  const stagePackage = (edit: {
    packageVersion?: string;
    builtVersion?: string;
    builtVersionName?: string;
  }): string => {
    const dir = mkdtempSync(join(outDir, 'pkg-'));
    mkdirSync(join(dir, 'scripts'), { recursive: true });
    mkdirSync(join(dir, 'src', 'packaging'), { recursive: true });
    cpSync(
      join(PACKAGE_ROOT, 'scripts', 'package-zip.mjs'),
      join(dir, 'scripts', 'package-zip.mjs'),
    );
    cpSync(
      join(PACKAGE_ROOT, 'src', 'packaging', 'store-zip.ts'),
      join(dir, 'src', 'packaging', 'store-zip.ts'),
    );
    cpSync(DIST, join(dir, 'dist'), { recursive: true });

    const pkg = readJson(PACKAGE_ROOT, 'package.json');
    if (edit.packageVersion !== undefined) pkg.version = edit.packageVersion;
    writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');

    if (edit.builtVersion !== undefined || edit.builtVersionName !== undefined) {
      const built = readJson(dir, 'dist', 'manifest.json');
      if (edit.builtVersion !== undefined) built.version = edit.builtVersion;
      if (edit.builtVersionName !== undefined) built.version_name = edit.builtVersionName;
      writeFileSync(join(dir, 'dist', 'manifest.json'), JSON.stringify(built, null, 2) + '\n');
    }
    return dir;
  };

  const runPackageZip = (dir: string) =>
    spawnSync(process.execPath, [join('scripts', 'package-zip.mjs')], {
      cwd: dir,
      encoding: 'utf8',
    });

  const archivesIn = (dir: string): string[] => {
    const out = join(dir, 'store-dist');
    return existsSync(out) ? readdirSync(out) : [];
  };

  // The positive control for the two refusals below, and the case that fails a
  // script rewritten to refuse everything.
  it('packages a bare, agreeing tree and names the archive from the package version', () => {
    const dir = stagePackage({});
    const packageVersion = String(readJson(dir, 'package.json').version);

    const run = runPackageZip(dir);

    expect(run.status, `package-zip failed:\n${run.stdout}\n${run.stderr}`).toBe(0);
    expect(archivesIn(dir)).toEqual([`plugin-browser-extension-${packageVersion}.zip`]);
  });

  it.each([
    [
      'a suffixed package version, with dist agreeing',
      {
        packageVersion: '0.10.0-beta.1',
        builtVersion: '0.10.0',
        builtVersionName: '0.10.0-beta.1',
      },
      /not a bare version/,
    ],
    [
      'a stale dist from an earlier build',
      { packageVersion: '0.10.0', builtVersion: '0.9.11' },
      /run `pnpm build`/,
    ],
    // The row above disagrees on Chrome's `version`, so the script reaches the
    // refusal whether or not it forwards what dist/ holds in `version_name`.
    // This one agrees there and disagrees only on the WHOLE version, so it is
    // the only case that pins the forwarding: dropping that spread from the call
    // leaves the pure function's own table green and packages a 0.10.0-beta.1
    // build as the stable 0.10.0. Measured green before this case existed.
    [
      'a pre-release dist left behind by its own stable',
      {
        packageVersion: '0.10.0',
        builtVersion: '0.10.0',
        builtVersionName: '0.10.0-beta.1',
      },
      /0\.10\.0-beta\.1/,
    ],
  ])('refuses %s, and writes no archive', (_label, edit, pattern) => {
    const dir = stagePackage(edit);

    const run = runPackageZip(dir);

    expect(run.status, `package-zip succeeded and must not:\n${run.stdout}`).not.toBe(0);
    // The archive is the property. An exit code alone would be satisfied by a
    // script that threw AFTER writing one, which is what an upload step globbing
    // store-dist/ would then pick up.
    expect(archivesIn(dir)).toEqual([]);
    expect(run.stderr).toMatch(pattern);
  });
});

describe('isLegalChromeVersion', () => {
  it.each([
    // One to four dot-separated integers, 0..65535, no leading zeros, not all
    // zero. There is no pre-release suffix in this field.
    ['0.0.0', false],
    ['0', false],
    ['1.2.3.999.5', false],
    ['01.2', false],
    ['65536', false],
    ['1.2.3-beta.1', false],
    ['1.2.3+build', false],
    ['1..2', false],
    ['', false],
    ['1', true],
    ['0.0.1', true],
    ['0.9.11', true],
    ['1.2.3.999', true],
    ['65535.65535.65535.65535', true],
  ])('%s is legal: %s', (version, legal) => {
    expect(isLegalChromeVersion(version)).toBe(legal);
  });
});
