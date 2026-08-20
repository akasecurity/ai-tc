/**
 * The clock that decides whether a timing breach may become PERMANENT.
 *
 * Nothing downstream can tell a bad reading from a good one: `checkRuleTiming`
 * compares whatever this returns against a floor, and a verdict of
 * `over-budget` is written to `rule_probe_cache` and never re-measured. So the
 * two ways this can quietly go wrong both have cases here — reading the wrong
 * resource (which mis-attributes another thread's work to the rule under
 * measurement) and reading nothing at all (which would either quarantine
 * everything or nothing, depending on which constant it degenerated to).
 */
import { Worker } from 'node:worker_threads';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { workClockMs } from '../src/work-clock.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

// How much work the worker below does. An ITERATION COUNT rather than a
// duration, so the CPU it burns is a property of the loop and not of how much
// core the scheduler gave it. Sized to cost far more than the floor below on
// any machine that runs this suite.
const WORKER_BURN_ITERATIONS = 200_000_000;

// What the positive control requires the worker to have spent. Well under the
// burn above on any machine, because its job is only to separate "the worker
// ran" from "the worker never started".
const WORKER_BURN_FLOOR_MS = 50;

// Burns CPU on whichever thread runs it. `sink` escapes so the loop cannot be
// optimised away, and the shape is duplicated into the worker below as source
// text because a worker cannot close over this one.
function burnCpu(iterations: number): number {
  let sink = 0;
  for (let i = 0; i < iterations; i++) sink += Math.sqrt(i + 1);
  return sink;
}

describe('workClockMs', () => {
  it('reads the calling thread, not the whole process', () => {
    // The binding, asserted directly. Behaviourally the two agree on any
    // single-threaded test, so a switch to `process.cpuUsage()` would leave
    // every other case in this file — and every timing suite in the workspace —
    // green while the product's pre-flight, which runs inside the scan worker,
    // started charging rules for the main thread's work and V8's background GC
    // and compiler threads. That error inflates, i.e. corroborates a stall,
    // which is the false accusation the corroboration exists to refuse.
    const perThread = vi.spyOn(process, 'threadCpuUsage');
    const perProcess = vi.spyOn(process, 'cpuUsage');

    workClockMs();

    expect(perThread).toHaveBeenCalled();
    expect(
      perProcess,
      'the pre-flight runs on the scan worker thread, so a process-wide reading charges the rule ' +
        'under measurement with every other thread in the process.',
    ).not.toHaveBeenCalled();
  });

  it('measures work rather than elapsed time', () => {
    const before = workClockMs();
    burnCpu(3_000_000);
    const spent = workClockMs() - before;
    // No upper bound: how long the burn takes is this machine's business. What
    // must hold is that real work moves the reading at all — a clock stuck at a
    // constant reports zero work for every rule, and every genuine breach then
    // reads as a stall and is never quarantined again.
    expect(spent).toBeGreaterThan(0);
  });

  it('does not move while another thread burns CPU', async () => {
    // The property the product actually depends on, and the only one a spy
    // cannot state. `process.cpuUsage()` would rise here by roughly the burn;
    // a per-thread reading must not.
    // Bounded by WORK, not by wall time, and that distinction is the same one
    // this whole module is about. A `while (Date.now() < until)` spin burns a
    // fixed amount of ELAPSED time, so on an oversubscribed runner it burns
    // whatever fraction of a core the scheduler hands it — at the contention
    // this repo has measured (96 burners on 14 cores) 400ms of wall buys about
    // 58ms of CPU, and any worse ratio drops under the floor the control
    // asserts below. A fixed iteration count burns the same CPU on a busy
    // machine as on an idle one; it just takes longer to do it.
    const worker = new Worker(
      `let sink = 0;
       for (let i = 0; i < ${String(WORKER_BURN_ITERATIONS)}; i++) sink += Math.sqrt(i + 1);
       require('node:worker_threads').parentPort.postMessage(sink);`,
      { eval: true },
    );
    try {
      const before = workClockMs();
      const processBefore = process.cpuUsage();
      await new Promise((resolve) => worker.once('message', resolve));
      const mine = workClockMs() - before;
      const after = process.cpuUsage();
      const wholeProcess =
        (after.user - processBefore.user + (after.system - processBefore.system)) / 1000;

      // The positive control. Without it this case passes on a worker that
      // never ran, and then the assertion below is about nothing — which is the
      // shape that would survive `workClockMs` being replaced by `() => 0`.
      //
      // The floor is a fraction of what the burn costs rather than a number
      // chosen against it: the iteration count above fixes the WORK, so a slow
      // machine takes longer but burns the same, and the only thing this has to
      // exclude is a worker that never ran at all.
      expect(
        wholeProcess,
        'the worker did not burn measurable CPU, so this case proves nothing about attribution',
      ).toBeGreaterThan(WORKER_BURN_FLOOR_MS);
      // This thread only awaited. It is allowed to have spent a little — the
      // await, the message, whatever GC landed here — but not the worker's burn.
      expect(mine).toBeLessThan(wholeProcess / 2);
    } finally {
      await worker.terminate();
    }
  });

  it('falls back to a process-wide reading rather than throwing where per-thread is absent', () => {
    // Unreachable on any platform this ships to (the API is present from Node
    // 22.15 / 23.9 and the floor here is 24), so this pins the DIRECTION of the
    // degradation rather than a live path. A throw would be the dangerous
    // outcome: `filterUnsafeRules` catches a throwing measurement and treats it
    // as a real failed attempt, which quarantines the rule and persists it — a
    // missing clock would condemn every uncached rule on the machine.
    // Order matters: the spy has to be installed BEFORE the copy is taken, or
    // the stubbed object carries the original function and the assertion below
    // asserts against a spy nothing can reach.
    const perProcess = vi.spyOn(process, 'cpuUsage');
    // Remove the binding rather than mocking its return: what is being modelled
    // is a runtime that never had the API, and a mock that returns `undefined`
    // tests a different failure (a present-but-broken API) whose fix is not this
    // one.
    //
    // Built with `Object.create` over the real `process` rather than by spreading
    // it. A spread copies own enumerable properties only, and `process` is an
    // EventEmitter whose `on`/`once`/`emit` live on the PROTOTYPE — a spread
    // stub therefore has none of them, and anything touching one while the global
    // is stubbed throws a TypeError that reads as a failure of the clock under
    // test. Today the stubbed window is synchronous so nothing does; that is a
    // property of this body rather than of the stub, and one `await` would end it.
    const withoutPerThread: NodeJS.Process = Object.create(process, {
      threadCpuUsage: { value: undefined, enumerable: true, configurable: true },
    }) as NodeJS.Process;
    vi.stubGlobal('process', withoutPerThread);
    try {
      const reading = workClockMs();
      expect(Number.isFinite(reading)).toBe(true);
      expect(perProcess).toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
