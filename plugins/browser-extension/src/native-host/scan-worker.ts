/**
 * Build entry for `native-host/scan-worker.js` — the isolated scan's worker
 * thread.
 *
 * Chrome never spawns it: it launches `native-host/host.js` per the manifest
 * `aka extension install` writes, and `@akasecurity/plugin-sdk`'s isolated
 * scanner then starts this worker BY PATH, resolved as a sibling of whichever
 * script is running. So it has to be emitted into the same `native-host/`
 * directory as the host.
 *
 * It has to be a real tsup entry rather than a file the loader finds at
 * `src/native-host/scan-worker.ts`: the installed extension ships the built
 * directory only, so a worker URL resolved against a source path points at a
 * file that was never packaged — and works perfectly in the repo and under
 * vitest right up until someone installs it. Without the sibling script,
 * `resolveWorkerUrl()` answers `undefined` and every rule that cannot be
 * bounded is dropped rather than run: built-in packs keep detecting, pulled
 * and custom rules silently do not. `handleCapture` builds a fresh runtime per
 * request, so that loss repeats on every captured message rather than once per
 * process, and `warnDegraded` announces it on a stderr that belongs to Chrome.
 */
import '@akasecurity/plugin-sdk/scan-worker';
