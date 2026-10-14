// One racing appender. It parks until every sibling thread has parked, then
// appends `count` login views to one session log, opened with the flags the
// parent chose, and reports how many it wrote.
// The barrier is what makes the appends overlap: threads started in a loop
// reach the write microseconds apart, so without it the case tests nothing.
//
// Node loads this file directly, outside the test runner's transform, so it
// imports only node: builtins and one source path whose own imports stay off
// the store layer.
import { parentPort, workerData } from 'node:worker_threads';

import { appendObservation } from '../../src/account/observation-log.ts';

interface AppendWorkerData {
  readonly stateDir: string;
  readonly sessionId: string;
  readonly bindingHash: string;
  readonly count: number;
  readonly shared: SharedArrayBuffer;
  readonly openFlags: number;
}

const ARRIVED = 0;
const RELEASE = 1;

const data = workerData as AppendWorkerData;
const slots = new Int32Array(data.shared);
Atomics.add(slots, ARRIVED, 1);
Atomics.notify(slots, ARRIVED);
Atomics.wait(slots, RELEASE, 0);
let written = 0;
for (let i = 0; i < data.count; i += 1) {
  const view = { t: Date.now(), bd: data.bindingHash, k: 'n' } as const;
  if (appendObservation(data.stateDir, data.sessionId, view, undefined, data.openFlags))
    written += 1;
}
parentPort?.postMessage({ written });
