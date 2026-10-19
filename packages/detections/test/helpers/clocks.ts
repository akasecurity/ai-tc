import type { ProbeClock } from '../../src/security/redos-probe.ts';

// The clocks the ReDoS gates read, in one place so the gates that compare
// readings from two of them agree about what each one is.

/** CPU consumed by this whole process, in ms. */
export const processCpuMs: ProbeClock = () => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

/**
 * CPU consumed by the calling thread, in ms. Unlike `processCpuMs` it is not
 * charged with V8's background GC and compiler threads, or with any other
 * thread of the process.
 */
export const threadCpuMs: ProbeClock = () => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};

export const wallMs: ProbeClock = () => performance.now();

/**
 * The smallest step `clock` was seen to advance by, in ms. A CPU clock that is
 * credited in whole scheduler ticks reads 15.6-16ms here on Windows; one kept
 * from the thread's own run time reads microseconds.
 *
 * Spins on the clock until it moves, several times, and keeps the smallest
 * step. Each spin is bounded so a clock that never moves reports Infinity
 * rather than hanging.
 */
export function clockResolutionMs(clock: ProbeClock, steps = 5): number {
  let smallest = Infinity;
  for (let i = 0; i < steps; i++) {
    const from = clock();
    const deadline = performance.now() + 200;
    let to = from;
    while (to === from && performance.now() < deadline) to = clock();
    if (to !== from) smallest = Math.min(smallest, to - from);
  }
  return smallest;
}

/**
 * The finest step at which a work clock can still give a ratio of two growth
 * readings. The growth tier judges a ratio only once the larger reading is
 * GROWTH_FLOOR_MS (5ms), so a step this size is 2% of the smallest reading it
 * compares.
 */
export const RATIO_RESOLUTION_MS = 0.1;

/** The step `threadCpuMs` advances by on this machine, measured once. */
export const THREAD_CPU_RESOLUTION_MS = clockResolutionMs(threadCpuMs);

/**
 * The clock a ratio of two timed readings is taken on: this thread's CPU time
 * where that clock is fine enough to give one, wall time where it is not.
 *
 * CPU time is the better instrument wherever it can be read finely. A thread
 * waiting for a core accrues none of it, so a machine with no free core for
 * the length of a whole measurement — which no number of wall-time samples
 * survives — moves neither side of the ratio. Where it is credited in whole
 * scheduler ticks (16ms on the Windows runner) a few-ms reading quantizes to
 * zero or one tick, and the ratio of two of them means nothing, so the wall
 * clock stands in; `corroborate` is then the thread CPU clock, for a caller
 * that can use a coarse reading of work alongside the wall reading.
 */
export const RATIO_CLOCK: { name: string; now: ProbeClock; corroborate: ProbeClock | undefined } =
  THREAD_CPU_RESOLUTION_MS <= RATIO_RESOLUTION_MS
    ? { name: 'thread CPU time', now: threadCpuMs, corroborate: undefined }
    : { name: 'wall time', now: wallMs, corroborate: threadCpuMs };
