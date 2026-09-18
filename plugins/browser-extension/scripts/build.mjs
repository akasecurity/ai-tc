#!/usr/bin/env node
// Orchestrates the TWO build outputs this package ships (the package is
// private and has no "files" field; cli/scripts/bundle-extension.mjs is what
// copies them into the CLI): a browser bundle (dist/ — background/content/popup + manifest +
// icons, esbuild) and a Node bundle (native-host/ — the native-messaging
// host, tsup — see ../tsup.config.ts for why it needs its own tool, not
// esbuild: the node:sqlite specifier fix and Node platform target).
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as esbuild from 'esbuild';

import { builtManifest } from '../src/packaging/store-zip.ts';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const watch = process.argv.includes('--watch');

const BROWSER_ENTRIES = {
  background: 'src/background.ts',
  content: 'src/content.ts',
  popup: 'src/popup/index.ts',
};

async function buildBrowser() {
  const entryPoints = Object.fromEntries(
    Object.entries(BROWSER_ENTRIES).map(([name, file]) => [name, join(root, file)]),
  );

  const options = {
    entryPoints,
    outdir: join(root, 'dist'),
    bundle: true,
    // IIFE everywhere (background included): MV3 service workers don't need
    // to be ES modules, and content scripts / the popup page can't load ESM
    // without extra manifest wiring this package doesn't need — one format
    // keeps the three entries interchangeable in how the manifest loads them.
    format: 'iife',
    platform: 'browser',
    target: 'chrome120',
    sourcemap: watch ? 'inline' : false,
    minify: !watch,
    logLevel: 'info',
  };

  if (watch) {
    const ctx = await esbuild.context(options);
    await ctx.watch();
  } else {
    await esbuild.build(options);
  }
}

function buildNativeHost() {
  // `shell` on Windows: pnpm is pnpm.cmd there, and Node refuses to execFile a
  // .cmd without a shell — so route the launcher through cmd.exe. No-op elsewhere.
  execFileSync('pnpm', ['exec', 'tsup', ...(watch ? ['--watch'] : [])], {
    cwd: root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
}

function copyStaticAssets() {
  mkdirSync(join(root, 'dist'), { recursive: true });
  // dist/manifest.json carries package.json's version. The source manifest
  // carries an all-zero one, which Chrome rejects — so a build output that
  // never reached this line cannot be loaded unpacked or uploaded to the store.
  // A pre-release package version is split across `version` and `version_name`,
  // since Chrome's `version` takes no suffix.
  const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const source = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  writeFileSync(
    join(root, 'dist', 'manifest.json'),
    JSON.stringify(builtManifest(source, version), null, 2) + '\n',
  );
  if (existsSync(join(root, 'icons'))) {
    cpSync(join(root, 'icons'), join(root, 'dist', 'icons'), { recursive: true });
  }
  const popupHtml = join(root, 'src', 'popup', 'popup.html');
  if (existsSync(popupHtml)) {
    cpSync(popupHtml, join(root, 'dist', 'popup.html'));
  }
}

async function main() {
  if (!watch) rmSync(join(root, 'dist'), { recursive: true, force: true });
  copyStaticAssets();
  await buildBrowser();
  // tsup --watch backgrounds its own file watcher; a plain build just runs once.
  buildNativeHost();
}

await main();
