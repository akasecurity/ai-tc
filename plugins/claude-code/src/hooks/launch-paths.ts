// Where the hook launcher (launch.ts) finds things, free of the launcher's own
// side effects so it can be tested: launch.ts loads a hook body on import.
import { basename, join } from 'node:path';

/**
 * Owner-only, the mode the rest of ~/.aka is created with (persistence's
 * DATA_DIR_MODE). Spelled here rather than imported because the launcher is
 * built on its own, and that import would bundle the store layer into it.
 */
export const CACHE_DIR_MODE = 0o700;

/** Where the compile cache is kept, under the given home directory. */
export function compileCacheDir(home: string): string {
  return join(home, '.aka', 'cache', 'compile');
}

/** The bundle a launcher built as `<name>.js` loads: `<name>.body.js` beside it. */
export function bodyScriptFor(launcherPath: string): string {
  return join(launcherPath, '..', `${basename(launcherPath, '.js')}.body.js`);
}
