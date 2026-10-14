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
 * opinion". The body keeps its own fail-open handling for everything after it
 * has loaded, and exits on its own. An exit from here is not added to the
 * fail-open count the body keeps: that counter writes through the store layer,
 * and the launcher bundles nothing it does not need before the cache is on.
 */
import { mkdirSync } from 'node:fs';
import { enableCompileCache } from 'node:module';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { bodyScriptFor, CACHE_DIR_MODE, compileCacheDir } from './launch-paths.ts';

async function launch(): Promise<void> {
  try {
    // Created here, owner-only, rather than left to Node: on a machine where
    // this is the first thing to touch ~/.aka, Node's own recursive create
    // would make ~/.aka itself with the default, wider mode.
    const dir = compileCacheDir(homedir());
    mkdirSync(dir, { recursive: true, mode: CACHE_DIR_MODE });
    enableCompileCache(dir);
  } catch {
    // No cache: the body is compiled from source, as it would be without one.
  }
  await import(pathToFileURL(bodyScriptFor(fileURLToPath(import.meta.url))).href);
}

try {
  await launch();
} catch {
  process.exit(0);
}
