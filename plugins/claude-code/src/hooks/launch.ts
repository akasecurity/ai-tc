/**
 * The script every hook command runs. It turns on Node's on-disk compile cache
 * and then loads the hook's own bundle, which sits beside it as
 * `<name>.body.js` for a launcher built as `<name>.js`.
 *
 * Each hook is a fresh `node` process per call, and its bundle is compiled from
 * source every time unless a cache holds the result. The cache has to be on
 * before the bundle is compiled, which for an ES module means before it is
 * imported at all — so the bundle is loaded from here, through a specifier the
 * bundler leaves alone, rather than imported statically.
 *
 * The cache lives under the user's own `~/.aka`, never a shared temporary
 * directory: what it holds is code this process will run.
 *
 * Fail-open, by the Claude Code convention: whatever goes wrong here — no
 * cache, a body that cannot be loaded or throws while it loads — the process
 * exits 0 having written nothing to stdout, which the host reads as "no
 * opinion". A body that cannot be loaded also writes one fixed line to stderr,
 * so a hook that scanned nothing is not indistinguishable from one that found
 * nothing. The cache is turned on through the module namespace rather than a
 * named import, so a Node without `enableCompileCache` links the launcher and
 * runs the hook uncached instead of failing to start it. The body keeps its own fail-open handling for everything after it
 * has loaded, and exits on its own. An exit from here is not added to the
 * fail-open count the body keeps: that counter writes through the store layer,
 * and the launcher bundles nothing it does not need before the cache is on.
 *
 * The work itself is runLauncher (launch-run.ts), which takes everything it
 * touches as arguments; this file only supplies the real ones.
 */
import { mkdirSync } from 'node:fs';
import * as nodeModule from 'node:module';
import { homedir } from 'node:os';

import { version as PLUGIN_VERSION } from '../../package.json';
import { runLauncher } from './launch-run.ts';

await runLauncher({
  launcherUrl: import.meta.url,
  pluginVersion: PLUGIN_VERSION,
  homedir,
  mkdirSync,
  // Read as possibly absent: present on every Node this plugin supports, but a
  // missing export must cost the cache, never the hook.
  enableCompileCache: (nodeModule as { enableCompileCache?: (dir: string) => unknown })
    .enableCompileCache,
  // A specifier the bundler leaves alone, so the body stays its own bundle.
  importBody: async (href) => {
    await import(href);
  },
  process,
});
