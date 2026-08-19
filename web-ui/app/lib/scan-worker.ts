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
 *
 * The one case worth a loud warning rather than a quiet fallback is `next
 * dev`/`next build`/`next start` invoked directly — `pnpm --filter
 * @akasecurity/web-ui dev`, or `cd web-ui && pnpm build && pnpm start` — which
 * bypasses the turbo task graph that builds this file (see turbo.json) and
 * succeeds anyway, with no other signal until someone runs a scan carrying a
 * pulled or custom rule. This warns on stderr, where a developer running one
 * of those commands is already looking (the same channel the pre-flight's own
 * quarantine line uses — see rule-quarantine.ts).
 */
export function scanWorkerUrl(): URL | undefined {
  const path = resolve(process.cwd(), ...SCAN_WORKER_RELATIVE_PATH.split('/'));
  if (existsSync(path)) return pathToFileURL(path);
  process.stderr.write(
    `[web-ui] ${SCAN_WORKER_RELATIVE_PATH} is missing, so the folder scan will drop every ` +
      'pulled or custom REGEX rule instead of bounding it. Run `pnpm turbo run build --filter=' +
      '@akasecurity/web-ui` (or `... run dev`) from the repo root, or `pnpm run build:worker` ' +
      'in web-ui/, before starting Next directly.\n',
  );
  return undefined;
}
