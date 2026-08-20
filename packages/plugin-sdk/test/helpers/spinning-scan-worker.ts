/**
 * A scan worker that answers every job correctly — but only after spending a
 * fixed stretch of wall-clock actually executing JavaScript first.
 *
 * The other four helpers here stand in for a worker that FAILS. This one stands
 * in for the thread the bound was built for: one that is busy, and that would
 * finish the work it is doing if nobody stopped it. That distinction is what
 * makes `terminate()` observable at all. A rule that never returns reports
 * nothing either way, so every observable the parent produces on a deadline —
 * the `timeout` outcome, the named culprit, the replacement thread — is
 * produced by the timer alone and survives the kill being removed entirely.
 * Work that WOULD have finished is the one thing whose absence proves the
 * thread stopped.
 *
 * It reports its own execution through the `SharedArrayBuffer` in
 * `spin-counters.ts` rather than by posting a message, because the parent
 * ignores every message from a thread it has already killed.
 *
 * The spin is bounded by wall-clock, not by an iteration count, for two
 * reasons: a test that stops working cannot hang the suite on it, and it ends
 * after about the same elapsed time whatever the machine, so a reader waiting
 * past it needs no knowledge of the hardware. It is a real busy loop rather
 * than an `Atomics.wait` because the property under test is that V8's execution
 * terminator interrupts code that is RUNNING.
 *
 * Node loads this file directly, so it stays on plain type annotations like the
 * worker it replaces.
 */
import { parentPort, workerData } from 'node:worker_threads';

import type {
  ScanWorkerData,
  ScanWorkerJob,
  ScanWorkerMessage,
} from '../../src/isolated-scan-protocol.ts';
import { COMPLETED, ENTERED, HEARTBEAT } from './spin-counters.ts';

/**
 * `ScanWorkerData` plus this fixture's own two fields. The real worker reads
 * neither, and nothing in `src/` ever sees this shape — it rides along in
 * `workerData` because that is the only channel the parent opens before the
 * thread starts.
 */
export interface SpinningWorkerData extends ScanWorkerData {
  /** The `spin-counters.ts` slots. */
  counters: SharedArrayBuffer;
  /** How long each job spends executing before it answers. */
  spinMs: number;
}

// Mirrors the real worker: loaded on the main thread there is no port to answer
// on and no `workerData` to destructure, so say so rather than failing on the
// line below.
if (!parentPort) throw new Error('[aka] spinning-scan-worker must be loaded on a worker thread');
const port = parentPort;

const { counters, spinMs } = workerData as SpinningWorkerData;
const slots = new Int32Array(counters);

port.on('message', (job: ScanWorkerJob) => {
  Atomics.add(slots, ENTERED, 1);
  const until = performance.now() + spinMs;
  while (performance.now() < until) {
    Atomics.add(slots, HEARTBEAT, 1);
  }
  Atomics.add(slots, COMPLETED, 1);
  // The verdict itself is uninteresting — every case here is about whether the
  // thread got this far, not about what it decided.
  //
  // ANNOTATED, and that is not decoration. This is a hand-written stand-in for
  // the real worker on the far side of a structured clone, so nothing checks it
  // against the protocol unless something says so here. Untyped, a protocol
  // change left this posting the old shape and the parent read the missing
  // field as a failed verdict — which surfaced as `expected [] to deeply equal
  // [rule]` in a case about thread lifetime, naming nothing to do with the
  // wire.
  const reply: ScanWorkerMessage =
    job.kind === 'probe'
      ? { kind: 'probed', id: job.id, verdict: 'safe', worstMs: 0, corroboratedMs: 0 }
      : { kind: 'result', id: job.id, findings: [] };
  port.postMessage(reply);
});

const ready: ScanWorkerMessage = { kind: 'ready' };
port.postMessage(ready);
