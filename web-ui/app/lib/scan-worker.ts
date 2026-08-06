import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Where the dashboard's ReDoS-bounding scan worker lives, and why it is found
// this way rather than beside the code that starts it.
//
// The scan worker is a thread the folder scan can KILL, which is the only way
// to interrupt a regex that never returns (see @akasecurity/local-ops'
// createGuardedFileScanner). The plugin finds its own copy as a sibling of the
// hook bundle that starts it, resolved from `import.meta.url`. That is exactly
// what cannot work here: a Next build REPLACES `import.meta.url` with the build
// machine's own absolute source path, baked into the server chunk as a string
// literal. On a user's machine that path does not exist, so the lookup finds
// nothing and the scan quietly loses its bound — and on the build machine it
// resolves, so every local check passes. Which is why the worker's location is
// this app's own input, stated once here.
//
// `process.cwd()` is the app directory in every way the dashboard runs:
//
//   - the published CLI's `aka dashboard` spawns the standalone server with cwd
//     set to the server's own directory, and Next's generated `server.js` also
//     `process.chdir`es to it;
//   - a dev/`next start` launch runs with cwd set to the web-ui package;
//   - vitest runs with cwd set to the same package.
//
// It is never a directory the user chose — the scan TARGET is user input, the
// app directory is not — so a hostile repo cannot get a `dist/scan-worker.js`
// of its own loaded by being scanned.

/**
 * The worker's path relative to the app directory, posix-spelled because
 * `next.config.ts` names the same file in `outputFileTracingIncludes` (which is
 * what copies it into the standalone build) and a glob there is posix. The
 * build emits it: see `tsup.config.ts`.
 */
export const SCAN_WORKER_RELATIVE_PATH = 'dist/scan-worker.js';

/**
 * The built scan worker, or undefined when this build did not produce one — a
 * real answer, not an error: the caller drops the rules it cannot bound and
 * reports them, rather than running them unbounded.
 */
export function scanWorkerUrl(): URL | undefined {
  const path = resolve(process.cwd(), ...SCAN_WORKER_RELATIVE_PATH.split('/'));
  return existsSync(path) ? pathToFileURL(path) : undefined;
}
