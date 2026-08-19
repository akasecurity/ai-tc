import type { InstallOrigin } from '@akasecurity/local-ops';

// Where the dashboard says the `aka` install it belongs to lives, so the
// Updates page can name the command that will actually update THIS copy.
//
// This is the same trap `app/lib/scan-worker.ts` documents, reached by a second
// door, and it has been measured on this code: a Next build REPLACES
// `import.meta.url` with the build machine's own absolute source path, baked
// into the server chunk as a string literal. `@akasecurity/local-ops` is in
// `transpilePackages`, so its classifier is compiled INTO that chunk and would
// read the maintainer's path rather than the user's. Nothing about that fails
// loudly: on the build machine the path resolves and every local check passes,
// while on a user's machine it resolves to nothing, the install classifies as
// unrecognised, and the Update button reports a failure quoting an absolute
// path from someone else's disk. Which is why the origin is this app's own
// input, stated once here.
//
// `process.cwd()` is the app directory in every way the dashboard runs — the
// same three cases scan-worker.ts relies on:
//
//   - the published CLI's `aka dashboard` spawns the standalone server with cwd
//     set to the server's own directory, which sits INSIDE the CLI install, so
//     the walk upward reaches the CLI's package.json;
//   - a dev/`next start` launch runs with cwd set to the web-ui package, whose
//     ancestor carries the workspace manifest — a source checkout;
//   - vitest runs with cwd set to that same package.
//
// It is never a directory the user chose, so nothing a scanned repo contains
// can steer it.
//
// A standalone-binary install needs none of this: a SEA is identified from
// `node:sea` and its own `execPath`, and `aka dashboard` runs the server by
// re-invoking that same binary, so the classifier sees the binary either way.

/**
 * The app directory, as the origin the install classifier walks up from.
 * Never `undefined` — `process.cwd()` always answers; if it points somewhere
 * unrecognisable the classifier says so rather than guessing a package manager.
 */
export function dashboardInstallOrigin(): InstallOrigin {
  return { moduleDir: process.cwd() };
}
