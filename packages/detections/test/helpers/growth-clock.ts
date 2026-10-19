import type { GrowthStatistic, ProbeClock } from '../../src/security/redos-probe.ts';

// The clock the growth tier reads in the bundled-rule gate, and the statistic
// that suits it.

/** CPU time consumed by the calling thread, in ms. */
export const threadCpuMs: ProbeClock = () => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};

const wallMs: ProbeClock = () => performance.now();

/**
 * The coarsest step a CPU clock may advance by and still resolve the 5-30ms
 * readings the growth tier judges. Linux accounts thread CPU time per scheduler
 * tick, a few ms; Windows advances it once per 15.6ms clock interrupt, which
 * quantizes those readings into a meaningless ratio.
 */
export const MAX_WORK_STEP_MS = 5;

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
  statistic: GrowthStatistic;
}

/**
 * CPU time, averaged, when `work` advances in steps of at most
 * `MAX_WORK_STEP_MS`; wall time, fastest-of-several, otherwise.
 */
export function growthClock(
  work: ProbeClock = threadCpuMs,
  wall: ProbeClock = wallMs,
): GrowthClock {
  return medianStepMs(work) <= MAX_WORK_STEP_MS
    ? { now: work, statistic: 'mean' }
    : { now: wall, statistic: 'fastest' };
}
