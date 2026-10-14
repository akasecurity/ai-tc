/**
 * A scan worker that starts cleanly, announces itself, and then never finishes
 * a job: every job spins on the thread until the parent terminates it.
 *
 * It stands in for a ruleset whose scan of one large field outlasts any budget
 * the caller can afford — the case the large-input bound exists for. Unlike
 * `spinning-scan-worker.ts` it takes nothing over `workerData`, because the
 * runtime builds the worker's data from its own ruleset and a test driving the
 * runtime has no channel to add fields to it. The spin is unbounded on purpose:
 * only `terminate()` ends it, so a parent that stopped killing the thread on
 * its deadline would leak a thread burning a core, never a result.
 *
 * Node loads this file directly, so it stays on plain type annotations like the
 * worker it replaces.
 */
import { parentPort } from 'node:worker_threads';

import type { ScanWorkerMessage } from '../../src/isolated-scan-protocol.ts';

if (!parentPort) throw new Error('[aka] endless-scan-worker must be loaded on a worker thread');
const port = parentPort;

port.on('message', () => {
  for (;;) {
    // Busy, not parked: the property under test is that the parent's deadline
    // interrupts code that is RUNNING.
  }
});

const ready: ScanWorkerMessage = { kind: 'ready' };
port.postMessage(ready);
