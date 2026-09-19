#!/usr/bin/env node
// Packages dist/ into the Chrome Web Store upload archive, at
// store-dist/<unscoped-name>-<version>.zip, and prints the path and the
// archive's sha256.
//
// It builds NOTHING: run `pnpm build` first. A missing dist/ is reported as
// that rather than as an empty archive; a dist/manifest.json still carrying the
// source tree's all-zero version is reported as an unstamped build; and a
// dist/ that disagrees with package.json, or a package version that is not a
// bare X.Y.Z, is refused by storeArchiveRefusal rather than packaged.
//
// The archive name comes from the package version and the package name, never
// from a glob over store-dist/ — a release step that resolves `*.zip` uploads
// whatever a previous run left there.
//
// The zip writer itself is src/packaging/store-zip.ts, which this imports under
// Node's built-in type stripping (Node 24 is the engines floor). This file stays
// .mjs: eslint.scripts.config.mjs spreads `networkGuard`, which carries no
// `files:` key and so lints .js/.mjs/.cjs only — a .ts here would be linted by
// nothing while reading as covered.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  isLegalChromeVersion,
  packagedManifest,
  storeArchiveRefusal,
  writeExtensionZip,
} from '../src/packaging/store-zip.ts';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, 'dist');
const builtManifestPath = join(dist, 'manifest.json');

const log = (m) => process.stdout.write(`package-zip: ${m}\n`);

if (!existsSync(builtManifestPath)) {
  throw new Error(
    `no built extension at ${dist} (${builtManifestPath} is missing) — run \`pnpm build\` first`,
  );
}

const built = JSON.parse(readFileSync(builtManifestPath, 'utf8'));
const version = String(built.version);
if (!isLegalChromeVersion(version)) {
  throw new Error(
    `built manifest version "${version}" is not a version Chrome accepts — ` +
      `${builtManifestPath} was not stamped by scripts/build.mjs`,
  );
}

// The store rules the archive has to satisfy before it is worth writing: a bare
// package version, and a dist/ that agrees with package.json. Both are decided in
// src/packaging/store-zip.ts, which is where they are tested; this throws the
// reason it returns.
const { name, version: packageVersion } = JSON.parse(
  readFileSync(join(root, 'package.json'), 'utf8'),
);
const refusal = storeArchiveRefusal(String(packageVersion), {
  version,
  ...(built.version_name === undefined ? {} : { version_name: String(built.version_name) }),
});
if (refusal !== undefined) throw new Error(refusal);

// Named from the PACKAGE version, not the manifest's: the refusal above has
// already established they are the same string, so the name says which version
// was asked for rather than which one dist/ happened to hold.
const archivePath = join(root, 'store-dist', `${basename(name)}-${packageVersion}.zip`);

rmSync(dirname(archivePath), { recursive: true, force: true });
mkdirSync(dirname(archivePath), { recursive: true });

const overrides = new Map([
  ['manifest.json', Buffer.from(JSON.stringify(packagedManifest(built), null, 2) + '\n')],
]);
const archive = writeExtensionZip(archivePath, dist, { overrides });
const sha256 = createHash('sha256').update(readFileSync(archivePath)).digest('hex');

log(`${archive.entries.length} entries, ${archive.byteLength} bytes`);
log(archivePath);
log(sha256);
