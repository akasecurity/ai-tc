import type { ProbeClock } from '../../src/security/redos-probe.ts';

// The clock the growth tier reads in the bundled-rule gate, and the step it
// advances by.

/** CPU time consumed by the calling thread, in ms. */
export const threadCpuMs: ProbeClock = () => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};

/**
 * The median distance between successive distinct readings of `read`, taken by
 * spinning until it advances `steps` times or `limitMs` of wall time pass.
 * `Infinity` when it advanced fewer than three times: too coarse to measure, or
 * not advancing at all.
 */
export function medianStepMs(read: ProbeClock, steps = 9, limitMs = 500): number {
  const seen: number[] = [];
  const deadline = performance.now() + limitMs;
  let previous = read();
  while (seen.length < steps && performance.now() < deadline) {
    const current = read();
    if (current === previous) continue;
    seen.push(current - previous);
    previous = current;
  }
  if (seen.length < 3) return Infinity;
  seen.sort((a, b) => a - b);
  return seen[Math.floor(seen.length / 2)] ?? Infinity;
}

export interface GrowthClock {
  now: ProbeClock;
  /** The step `now` advances by, which sizes each reading's window. */
  stepMs: number;
}

/**
 * The scanning thread's CPU time, with its measured step. Linux accounts it per
 * scheduler tick, a few ms; Windows advances it once per 15.6ms clock
 * interrupt; macOS in microseconds. The growth tier windows each reading to
 * span several steps (`windowReadingMs`), so the one clock serves on all
 * three. A step that cannot be measured is `Infinity`, which the tier refuses
 * rather than reading a single scan on a clock nobody sized.
 *
 * The wall clock is never used: on a loaded runner elapsed time grows with the
 * input faster than the work does — a scan that allocates fresh pages on every
 * call is rescheduled around each page fault — so a linear rule reads as
 * superlinear, and as over the budget, on readings that were the machine's.
 */
export function growthClock(work: ProbeClock = threadCpuMs, limitMs = 2_000): GrowthClock {
  return { now: work, stepMs: medianStepMs(work, 9, limitMs) };
}
