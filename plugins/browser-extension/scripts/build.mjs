#!/usr/bin/env node
// Orchestrates the TWO build outputs this package ships (the package is
// private and has no "files" field; cli/scripts/bundle-extension.mjs is what
// copies them into the CLI): a browser bundle (dist/ — background/content/popup + manifest +
// icons, esbuild) and a Node bundle (native-host/ — the native-messaging
// host, tsup — see ../tsup.config.ts for why it needs its own tool, not
// esbuild: the node:sqlite specifier fix and Node platform target).
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as esbuild from 'esbuild';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const watch = process.argv.includes('--watch');

const BROWSER_ENTRIES = {
  background: 'src/background.ts',
  content: 'src/content.ts',
  popup: 'src/popup/index.ts',
  // The MAIN-world network tap. It is its own entry rather than part of
  // content.js because it runs in the page's own JS context: bundling it with
  // anything else would put that code in the page too, and the bundle guard in
  // test/tap-bundle.test.ts reads this emitted file expecting a tap and
  // nothing more.
  tap: 'src/tap.ts',
  // The isolated-world half of the network capture. Its own entry because the
  // manifest loads it as a separate content script at document_start, so its
  // window listener is in place before the tap posts its handshake.
  bridge: 'src/bridge.ts',
};

// The endpoints the MAIN-world tap forwards, compiled INTO the bundle rather
// than sent to it. The tap takes no commands: it shares the page's window event
// target, so a table it could be told at runtime is a table the page could set,
// and what the tap forwards is what AKA goes on to persist.
//
// Each entry is `{ host, path }` — an exact host and a RegExp source the tap
// anchors at the start of the path. The host half is not decoration: a bare
// pattern tested against a whole URL forwards any origin that happens to carry
// the pattern text, and the tap runs on pages whose own script chooses the
// origins it fetches.
//
// DERIVED from src/providers/registry.ts, never written here: the adapters are
// what declare a site's endpoints, and a second hand-kept copy is a tap that
// silently observes something other than what the adapters parse. The
// derivation and every check on it live in src/tap-endpoints.ts, which this
// imports directly (Node strips the types) so there is no second transformation
// to get wrong.
//
// It REFUSES rather than falling back. An empty table is indistinguishable from
// a working tap that matches nothing, so a build that cannot read the registry
// has to stop: a silent `[]` here ships an extension that reports itself
// installed and observes no traffic at all.
//
// Every `path` here must be LINEAR, and that is a rule about where it runs.
// The tap compiles each one to `new RegExp('^(?:…)')` and tests it
// SYNCHRONOUSLY on the page's own fetch/send call path, against a path and
// query the PAGE chose — the same exposure the isolated-scan bound exists for,
// except the cost lands on the user's tab rather than on a hook, where nothing
// can interrupt it and there is no deadline to blow. So: anchored, no nested
// quantifiers, and no alternation over overlapping prefixes. The patterns are
// repo-authored, which is why this is a discipline note and not a hole — a
// pattern that cannot be written that way belongs behind the same probe
// battery a pulled pack goes through, not in this table.
async function tapEndpoints() {
  const module = pathToFileURL(join(root, 'src', 'tap-endpoints.ts')).href;
  let table;
  try {
    ({ TAP_ENDPOINTS: table } = await import(module));
  } catch (cause) {
    throw new Error(
      'cannot read the adapter registry to generate the tap endpoint table — refusing to ' +
        'build a tap that would match nothing',
      { cause },
    );
  }
  if (!Array.isArray(table)) {
    throw new Error('the adapter registry produced no endpoint table — refusing to build');
  }
  return table;
}

async function buildBrowser() {
  const endpoints = await tapEndpoints();
  const entryPoints = Object.fromEntries(
    Object.entries(BROWSER_ENTRIES).map(([name, file]) => [name, join(root, file)]),
  );

  const options = {
    entryPoints,
    outdir: join(root, 'dist'),
    define: {
      // Substituted into src/tap.ts's `declare const`. Only the tap references
      // the name, so the other entries are unaffected.
      AKA_TAP_ENDPOINTS: JSON.stringify(endpoints),
    },
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
  cpSync(join(root, 'manifest.json'), join(root, 'dist', 'manifest.json'));
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
