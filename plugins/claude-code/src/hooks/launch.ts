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
 */
import { mkdirSync } from 'node:fs';
import * as nodeModule from 'node:module';
import { homedir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { version as PLUGIN_VERSION } from '../../package.json';
import {
  BODY_LOAD_FAILED,
  bodyScriptFor,
  CACHE_DIR_MODE,
  compileCacheDir,
} from './launch-paths.ts';

// Read as possibly absent: present on every Node this plugin supports, but a
// missing export must cost the cache, never the hook.
const enableCompileCache = (nodeModule as { enableCompileCache?: (dir: string) => unknown })
  .enableCompileCache;

async function launch(): Promise<void> {
  try {
    // Created here, owner-only, rather than left to Node: on a machine where
    // this is the first thing to touch ~/.aka, Node's own recursive create
    // would make ~/.aka itself with the default, wider mode.
    if (enableCompileCache !== undefined) {
      const dir = compileCacheDir(homedir(), PLUGIN_VERSION);
      mkdirSync(dir, { recursive: true, mode: CACHE_DIR_MODE });
      enableCompileCache(dir);
    }
  } catch {
    // No cache: the body is compiled from source, as it would be without one.
  }
  await import(pathToFileURL(bodyScriptFor(fileURLToPath(import.meta.url))).href);
}

try {
  await launch();
} catch {
  // Exit from the write's callback: process.exit does not wait for a pending
  // pipe write, so exiting straight after it can drop the line.
  const exit = (): void => {
    process.exit(0);
  };
  try {
    process.stderr.write(`${BODY_LOAD_FAILED}\n`, exit);
  } catch {
    exit();
  }
}
