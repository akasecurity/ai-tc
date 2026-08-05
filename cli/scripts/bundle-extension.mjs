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
import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

// Stamp the bundled manifest's version from the CLI's own — the extension is
// a shipped artifact of the CLI release line, and chrome://extensions shows
// this number. The source manifest keeps a fixed placeholder so the version
// bump stays a five-file release concern (see CLAUDE.md's Releasing section).
const cliVersion = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8')).version;
const bundledManifestPath = join(extensionDest, 'manifest.json');
const bundledManifest = JSON.parse(readFileSync(bundledManifestPath, 'utf8'));
bundledManifest.version = cliVersion;
writeFileSync(bundledManifestPath, JSON.stringify(bundledManifest, null, 2) + '\n');
log(`stamped extension manifest version ${cliVersion}`);

const hostDest = join(cliDir, 'native-host');
rmSync(hostDest, { recursive: true, force: true });
cpSync(hostSrcDir, hostDest, { recursive: true });

log(`bundled extension → ${extensionDest}`);
log(`bundled native host → ${join(hostDest, 'host.js')}`);
