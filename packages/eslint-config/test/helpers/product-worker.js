import workerThreads from 'node:worker_threads';
import { Worker } from 'node:worker_threads';

// The two shapes real code reaches `Worker` through, kept apart on purpose.
//
// The guard installs itself over BOTH by two separate mechanisms — assigning
// the module property, then re-syncing the builtin ESM facade — and either one
// alone leaves half the call sites unguarded. Driving only one shape would let
// the missing half ship green, so each export below is covered by its own case
// and each fails to a different mutation of the guard.
//
// This file also puts the call site in a module the test did not write inline,
// which is where a product call site actually lives: `@akasecurity/plugin-sdk`'s
// isolated scan spawns the scan worker from `isolated-scan.ts`, not from a test.

/**
 * A NAMED import, bound when this module first loads. This is the shape
 * `isolated-scan.ts` uses, and it reads the facade's snapshot rather than the
 * module object — so it is guarded only by `syncBuiltinESMExports()`.
 * @param {string} source an ES module body, run with `eval: true`
 */
export function spawnViaNamedImport(source) {
  return new Worker(source, { eval: true });
}

/**
 * A namespace import, read off the module object at CALL time — so it is
 * guarded by the property assignment and would survive the facade never being
 * re-synced.
 * @param {string} source an ES module body, run with `eval: true`
 */
export function spawnViaNamespace(source) {
  return new workerThreads.Worker(source, { eval: true });
}
