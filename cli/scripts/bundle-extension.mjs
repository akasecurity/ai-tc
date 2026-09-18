#!/usr/bin/env node
// Build plugins/browser-extension (its own build produces BOTH outputs in one
// pass: the browser bundle in dist/ and the Node native-messaging host in
// native-host/ — see plugins/browser-extension/scripts/build.mjs) and copy
// both into the CLI package, so `aka extension install` (cli/src/commands/
// extension.ts, which locates them at <package>/extension and
// <package>/native-host) works from a published npm install, not just a
// workspace checkout. Same "build once, copy into cli/" shape as
// bundle-web-ui.mjs.
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(cliDir, '..');
const extensionDir = join(repoRoot, 'plugins', 'browser-extension');

const log = (m) => process.stdout.write(`bundle-extension: ${m}\n`);

log('building @akasecurity/plugin-browser-extension…');
// `shell` on Windows: pnpm is pnpm.cmd there, and Node refuses to execFile a .cmd
// without a shell — so route the launcher through cmd.exe. No-op elsewhere.
execFileSync('pnpm', ['turbo', 'run', 'build', '--filter=@akasecurity/plugin-browser-extension'], {
  cwd: repoRoot,
  stdio: 'inherit',
  shell: process.platform === 'win32',
});

const distSrc = join(extensionDir, 'dist');
const hostSrcDir = join(extensionDir, 'native-host');
const hostSrc = join(hostSrcDir, 'host.js');
if (!existsSync(distSrc)) throw new Error(`extension dist not found at ${distSrc}`);
if (!existsSync(hostSrc)) throw new Error(`native host script not found at ${hostSrc}`);

const extensionDest = join(cliDir, 'extension');
rmSync(extensionDest, { recursive: true, force: true });
cpSync(distSrc, extensionDest, { recursive: true });

// The bundled manifest's version is NOT stamped here. It comes from the
// extension's own package.json, which plugins/browser-extension/scripts/
// build.mjs writes into dist/manifest.json, and this checks it against the
// CLI's: chrome://extensions shows that number and the native host stamps the
// same package.json version into every session, so one tarball recording two
// different versions is a release defect rather than something to paper over.
//
// Chrome's `version` takes no pre-release suffix, so a suffixed package version
// is built as its numeric core in `version` plus the whole string in
// `version_name`. Both halves are checked: the whole string must be the CLI's,
// and `version` must be that string's core.
const cliVersion = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8')).version;
const cliCore = cliVersion.split(/[-+]/, 1)[0];
const bundledManifestPath = join(extensionDest, 'manifest.json');
const bundledManifest = JSON.parse(readFileSync(bundledManifestPath, 'utf8'));
const bundledVersion = bundledManifest.version_name ?? bundledManifest.version;
if (bundledVersion !== cliVersion || bundledManifest.version !== cliCore) {
  throw new Error(
    `extension manifest version ${bundledVersion} (version field ${bundledManifest.version}) ` +
      `does not match the CLI's ${cliVersion} — plugins/browser-extension/package.json and ` +
      `cli/package.json must carry the same version`,
  );
}
log(`bundled extension manifest version ${bundledVersion}`);

const hostDest = join(cliDir, 'native-host');
rmSync(hostDest, { recursive: true, force: true });
cpSync(hostSrcDir, hostDest, { recursive: true });

log(`bundled extension → ${extensionDest}`);
log(`bundled native host → ${join(hostDest, 'host.js')}`);
