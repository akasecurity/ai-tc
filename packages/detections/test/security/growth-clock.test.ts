import { describe, expect, it } from 'vitest';

import type { ProbeClock } from '../../src/security/redos-probe.ts';
import { growthClock, medianStepMs, threadCpuMs } from '../helpers/growth-clock.ts';

// A clock that advances by `step` once every `reads` reads, as a tick-accounted
// CPU clock does while a thread spins on it.
function ticking(step: number, reads = 50): ProbeClock {
  let taken = 0;
  return () => Math.floor(taken++ / reads) * step;
}

describe('the growth tier clock', () => {
  it('reads the step of a clock that advances in ticks', () => {
    expect(medianStepMs(ticking(4))).toBeCloseTo(4);
    expect(medianStepMs(ticking(15.6))).toBeCloseTo(15.6);
  });

  it('reads no step from a clock that does not advance', () => {
    expect(medianStepMs(() => 0, 9, 5)).toBe(Infinity);
  });

  it('reads no step from a clock that advances only twice in the time allowed', () => {
    let taken = 0;
    const stalled: ProbeClock = () => Math.min(Math.floor(taken++ / 50), 2);
    expect(medianStepMs(stalled, 9, 5)).toBe(Infinity);
  });

  it('takes the median step, so one short update between ticks does not decide it', () => {
    const steps = [4, 4, 0.2, 4, 4, 4, 4, 0.3, 4, 4];
    let time = 0;
    let index = 0;
    let taken = 0;
    const read: ProbeClock = () => {
      if (taken++ % 20 === 0) time += steps[index++ % steps.length] ?? 0;
      return time;
    };
    expect(medianStepMs(read)).toBeCloseTo(4);
  });

  it('reads the step of the work clock it is given', () => {
    const work = ticking(4);
    expect(growthClock(work)).toEqual({ now: work, stepMs: 4 });
    expect(growthClock(ticking(15.6)).stepMs).toBeCloseTo(15.6);
  });

  it('reports a work clock that does not advance as unmeasured, which the tier refuses', () => {
    expect(growthClock(() => 0, 5).stepMs).toBe(Infinity);
  });

  it('thread CPU time advances while this thread works', () => {
    // A clock stuck at a constant would pass the case below and measure as
    // infinitely coarse. The fresh-thread re-measurement in redos.test.ts
    // reads it too.
    const before = threadCpuMs();
    let spun = 0;
    for (let i = 0; i < 100_000_000; i++) spun += i % 7;
    expect(spun).toBeGreaterThan(0);
    expect(threadCpuMs()).toBeGreaterThan(before);
  });

  it('thread CPU time does not count time spent waiting', () => {
    const before = threadCpuMs();
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60);
    expect(threadCpuMs() - before).toBeLessThan(30);
  });
});
