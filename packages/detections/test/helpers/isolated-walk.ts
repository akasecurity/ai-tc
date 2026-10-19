import { Worker } from 'node:worker_threads';

import type { Rule } from '@akasecurity/schema';

/** What `worstProbeMs` measured for a rule on a fresh thread. */
export interface IsolatedWalk {
  /** The worst probe's CPU time on that thread, in ms. */
  ms: number;
  /** The probe that cost `ms`. */
  probe: string;
  probeLength: number;
}

/**
 * Runs the probe walk for `rule` on a new worker thread, charged with that
 * thread's own CPU time.
 *
 * A new thread is a new V8 isolate, and V8 keeps compiled regexes per isolate,
 * so every pattern starts there in the bytecode interpreter exactly as it does
 * in a fresh hook process. That is what makes this a re-measurement of the
 * same cost rather than of a cheaper one: re-running the walk on the thread
 * that already ran it measures the natively compiled tier instead, which is
 * several times faster for a backtracking pattern and would admit a rule the
 * first walk rightly condemned.
 *
 * The thread's CPU clock is not charged with the GC and compiler threads, nor
 * with whatever the test's own thread did, and nothing else runs on it.
 */
export function walkInIsolation(rule: Rule): Promise<IsolatedWalk> {
  const worker = new Worker(new URL('./isolated-walk-worker.ts', import.meta.url), {
    workerData: rule,
  });
  return new Promise<IsolatedWalk>((resolve, reject) => {
    worker.once('message', (walk: IsolatedWalk) => {
      resolve(walk);
    });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      reject(new Error(`the isolated walk exited (code ${String(code)}) before reporting`));
    });
  }).finally(() => void worker.terminate());
}
