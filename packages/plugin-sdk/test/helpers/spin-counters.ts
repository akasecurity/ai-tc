/**
 * The shared-memory wire between a spinning scan worker and the test watching
 * it.
 *
 * A terminated thread cannot report anything about itself, and the parent drops
 * every message from a thread it has already killed — so a message channel can
 * never answer "is that thread still running?". Memory both sides can read can:
 * these three counters live in a `SharedArrayBuffer` handed to the worker over
 * `workerData`, and the worker's writes are visible to the reader whether or not
 * the parent is still listening to it.
 *
 * It sits in a module of its own because both sides read it. A slot index each
 * side spelled for itself would be free to disagree, and the direction it would
 * fail in is the quiet one: a reader watching the wrong slot sees zero movement
 * and reports the thread as stopped.
 *
 * That failure is what the two control cases in `isolated-scan.test.ts` exist
 * for — they drive the same fixture with no deadline and require the counters
 * to move. A counter that can never move satisfies every absence assertion
 * here, so weakening one of these slots has to redden something.
 *
 * Node loads the worker directly, so this file stays on plain type annotations.
 */

/** Bumped once per job, before the spin starts. */
export const ENTERED = 0;
/**
 * Bumped on every iteration of the spin. Movement between two reads means the
 * thread executed an instruction between them; no movement means it did not.
 */
export const HEARTBEAT = 1;
/** Bumped when a spin runs to its natural end instead of being interrupted. */
export const COMPLETED = 2;

const SLOT_COUNT = 3;

export interface SpinCounters {
  /** Handed to the worker over `workerData`. */
  buffer: SharedArrayBuffer;
  entered(): number;
  heartbeat(): number;
  completed(): number;
}

export function spinCounters(): SpinCounters {
  const buffer = new SharedArrayBuffer(SLOT_COUNT * Int32Array.BYTES_PER_ELEMENT);
  const slots = new Int32Array(buffer);
  return {
    buffer,
    entered: () => Atomics.load(slots, ENTERED),
    heartbeat: () => Atomics.load(slots, HEARTBEAT),
    completed: () => Atomics.load(slots, COMPLETED),
  };
}
