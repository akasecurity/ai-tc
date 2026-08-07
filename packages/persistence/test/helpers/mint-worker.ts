/**
 * One racing minter: parks on a barrier until every sibling thread is parked
 * too, then takes a first-use key on a shared data dir.
 *
 * Two targets, because the store keeps two machine-local keys behind the same
 * read-then-mint shape. `fingerprint` is the exception key; `vault` is the vault
 * keyring, whose loss is worse — a lost epoch does not orphan a grant, it leaves
 * ciphertext that cannot be opened.
 *
 * The barrier is what makes the race real rather than hopeful. Threads started
 * in a loop reach the mint microseconds apart and the first one is usually done
 * before the last one has started, so a plain `for` loop of workers tests
 * nothing. Here each thread announces itself in shared memory and then blocks;
 * the starting thread releases them all with one store, so every thread is
 * inside the absence-check window at the same instant.
 *
 * Being released together is necessary but not sufficient, so this also COUNTS
 * the overlap: a thread bumps `INSIDE` around the call and raises `MAX_INSIDE`
 * to the highest simultaneous occupancy any thread saw. The starting thread
 * reads that afterwards, because "they were all parked" and "at least two of
 * them were in the mint at once" are different claims and only the second one
 * makes convergence non-trivial.
 *
 * Slots: 0 arrivals, 1 the release, 2 current occupancy, 3 the high-water mark.
 *
 * Failure is reported as a message, never thrown: a throw here surfaces on the
 * starting thread as an 'error' event, and that thread is parked in
 * `Atomics.wait` while the barrier fills, so an early failure would be
 * delivered long after the test that caused it moved on.
 *
 * This file is loaded by Node directly, outside the test runner's transform, so
 * it stays on node: builtins, plain type annotations, and a source import the
 * runtime can resolve on its own.
 */
import { parentPort, workerData } from 'node:worker_threads';

import { loadOrCreateFingerprintKey } from '../../src/fingerprint.ts';
import { FileKeyProvider } from '../../src/vault/key-provider.ts';

const ARRIVED = 0;
const RELEASE = 1;
const INSIDE = 2;
const MAX_INSIDE = 3;

interface MintWorkerData {
  dataDir: string;
  target: 'fingerprint' | 'vault';
  shared: SharedArrayBuffer;
}

/** What one racing thread ended up holding — material as hex, for comparison. */
export interface MintOutcome {
  ok: true;
  version: number;
  material: string;
}

export interface MintFailure {
  ok: false;
  message: string;
}

const { dataDir, target, shared } = workerData as MintWorkerData;
const signal = new Int32Array(shared);

function report(result: MintOutcome | MintFailure): void {
  parentPort?.postMessage(result);
}

async function mint(): Promise<{ version: number; material: Buffer }> {
  if (target === 'vault') return new FileKeyProvider(dataDir).loadOrCreate();
  return loadOrCreateFingerprintKey(dataDir);
}

// Raise the high-water mark to `seen` if it is still lower. compareExchange
// rather than a plain store: two threads entering at once would otherwise race
// and the later, LOWER write would win.
function raiseMaxInside(seen: number): void {
  let max = Atomics.load(signal, MAX_INSIDE);
  while (seen > max) {
    const prev = Atomics.compareExchange(signal, MAX_INSIDE, max, seen);
    if (prev === max) return;
    max = prev;
  }
}

// Announce arrival, then park until the starting thread releases the barrier.
// The notify matters: the starting thread is blocked on this slot waiting for
// the count to reach its worker total.
Atomics.add(signal, ARRIVED, 1);
Atomics.notify(signal, ARRIVED);
Atomics.wait(signal, RELEASE, 0);

try {
  raiseMaxInside(Atomics.add(signal, INSIDE, 1) + 1);
  try {
    const key = await mint();
    report({ ok: true, version: key.version, material: key.material.toString('hex') });
  } finally {
    Atomics.sub(signal, INSIDE, 1);
  }
} catch (err) {
  report({ ok: false, message: err instanceof Error ? err.message : String(err) });
}
