/**
 * The sampling ORDER the two-size ratio suites rely on, pinned without a clock.
 *
 * Every property here is about which call runs when, never about how long it
 * takes, so the probes are stubs that record themselves and return a constant.
 * A timing assertion would be the wrong instrument: each of these properties can
 * break while every ratio in `test/performance/` stays green.
 */
import { describe, expect, it } from 'vitest';

import type { InterleavedCall, Side } from './interleaved-samples.ts';
import { sampleInterleaved, timeCall } from './interleaved-samples.ts';

function label(call: InterleavedCall<string>): string {
  return `${call.name}${String(call.iteration)}:${call.side}`;
}

describe('sampleInterleaved', () => {
  it('holds exactly `samples` readings per probe on each store', async () => {
    const names = ['stats', 'list', 'detail'] as const;
    const paired = await sampleInterleaved(names, 25, () => 1);
    for (const name of names) {
      expect(paired.small[name], `${name} small`).toHaveLength(25);
      expect(paired.large[name], `${name} large`).toHaveLength(25);
    }
  });

  it('records each reading on the store that produced it, in iteration order', async () => {
    const paired = await sampleInterleaved(['read'], 4, ({ side, iteration }) =>
      side === 'small' ? 100 + iteration : 200 + iteration,
    );
    expect(paired.small.read).toEqual([100, 101, 102, 103]);
    expect(paired.large.read).toEqual([200, 201, 202, 203]);
  });

  it('interleaves the stores one probe block at a time, alternating which goes first', async () => {
    const calls: string[] = [];
    await sampleInterleaved(['a', 'b'], 3, (call) => {
      calls.push(label(call));
      return 0;
    });
    expect(calls).toEqual([
      'a0:small',
      'a0:large',
      'a1:large',
      'a1:small',
      'a2:small',
      'a2:large',
      // The second block enters on the store the first block did not.
      'b0:large',
      'b0:small',
      'b1:small',
      'b1:large',
      'b2:large',
      'b2:small',
    ]);
  });

  it('gives each store the lead equally often across an even number of blocks, whatever `samples` is', async () => {
    // Odd on purpose: 25 is what the page suites take, and within one block an
    // odd count cannot split the lead evenly — alternating block entry is what
    // balances it across the probes.
    const leads: Record<Side, number> = { small: 0, large: 0 };
    let previous = 0;
    let calls = 0;
    await sampleInterleaved(['a', 'b', 'c', 'd'], 25, (call) => {
      if (calls % 2 === 0) leads[call.side] += 1;
      calls += 1;
      previous = call.iteration;
      return 0;
    });
    expect(previous).toBe(24);
    expect(leads).toEqual({ small: 50, large: 50 });
  });

  it('releases un-awaited continuations between blocks, and not within one', async () => {
    let settled = false;
    const seen: boolean[] = [];
    await sampleInterleaved(['a', 'b'], 2, ({ name, iteration, side }) => {
      if (name === 'a' && iteration === 0 && side === 'small') {
        void Promise.resolve().then(() => {
          settled = true;
        });
      }
      seen.push(settled);
      return 0;
    });
    // The control: nothing inside a block yields, so a continuation queued on
    // the block's first call is still pending on its last. Without it, the check
    // below could pass because continuations drain on every call.
    expect(seen.slice(0, 4)).toEqual([false, false, false, false]);
    expect(seen.slice(4)).toEqual([true, true, true, true]);
  });
});

describe('timeCall', () => {
  it('calls the work once and returns a non-negative elapsed time', () => {
    let calls = 0;
    const elapsed = timeCall(() => {
      calls += 1;
    });
    expect(calls).toBe(1);
    expect(elapsed).toBeGreaterThanOrEqual(0);
  });

  it('handles the rejection of a promise the work returns, so a broken probe is never unhandled', async () => {
    const unhandled: unknown[] = [];
    const record = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', record);
    try {
      timeCall(() => Promise.reject(new Error('probe failed')));
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    } finally {
      process.off('unhandledRejection', record);
    }
    expect(unhandled).toEqual([]);
  });
});
