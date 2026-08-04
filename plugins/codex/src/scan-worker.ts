/**
 * Build entry for `scripts/scan-worker.js` — the isolated scan's worker thread.
 *
 * It is the one emitted script `hooks.json` never names: nothing spawns it as a
 * hook. `@akasecurity/plugin-sdk`'s isolated scanner starts it by path, from
 * whichever hook script is running, and every hook script lands in the same
 * `scripts/` directory as this one.
 *
 * It has to be a real entry rather than a file the loader finds at
 * `src/scan-worker.ts`: the published plugin ships `scripts/` only, so a worker
 * URL resolved against a source path would point at a file that was never
 * shipped — and would work perfectly in the repo and under vitest right up
 * until someone installed it. Without the sibling script, `resolveWorkerUrl()`
 * answers `undefined` and every rule that cannot be bounded is dropped rather
 * than run: built-in packs keep detecting, pulled and custom rules silently do
 * not.
 */
import '@akasecurity/plugin-sdk/scan-worker';
