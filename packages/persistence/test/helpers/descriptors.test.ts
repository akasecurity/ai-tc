/**
 * The probe's own guard. Every assertion built on it is an ABSENCE assertion —
 * "this path leaked nothing" — and a broken counter satisfies all of them at
 * once, so the cases that matter most here are the ones proving it reports a
 * leak that is really there.
 */
import { closeSync, openSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { descriptorProbe } from './descriptors.ts';

describe('descriptorProbe', () => {
  it('is observable on this platform, or says why not', () => {
    const probe = descriptorProbe();
    // Not `toBe(true)`: Windows has no /dev/fd and is expected to report false.
    // What must hold either way is that an unusable probe carries its reason —
    // a caller skipping with `undefined` prints no explanation at all.
    if (probe.observable) {
      expect(probe.reason).toBeUndefined();
    } else {
      expect(probe.reason).toBeTruthy();
    }
  });

  it('reports nothing leaked when the thunk opens nothing', (ctx) => {
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');
    let ran = false;
    expect(
      probe.leakedBy(() => {
        ran = true;
      }),
    ).toBe(0);
    // Without this the case would also pass on a thunk that never ran.
    expect(ran).toBe(true);
  });

  it('reports a descriptor the thunk left open', (ctx) => {
    // The positive control. Without this the suite proves only that the probe
    // says zero — which it would also say with `readCount` stubbed to a
    // constant, and every leak assertion downstream would pass forever.
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');

    let escaped = -1;
    const leaked = probe.leakedBy(() => {
      escaped = openSync(process.execPath, 'r');
    });
    closeSync(escaped);

    expect(leaked).toBe(1);
  });

  it('reports one per leak, so the count scales rather than merely flipping', (ctx) => {
    // A probe that answered "1 for any leak" would pass the case above and still
    // hide four of five leaked handles — which is exactly the shape a failed
    // open produces, one per retry.
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');

    const escaped: number[] = [];
    const leaked = probe.leakedBy(() => {
      for (let i = 0; i < 5; i += 1) escaped.push(openSync(process.execPath, 'r'));
    });
    for (const fd of escaped) closeSync(fd);

    expect(leaked).toBe(5);
  });

  it('reports nothing leaked when the thunk closes what it opened', (ctx) => {
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');

    const leaked = probe.leakedBy(() => {
      const fd = openSync(process.execPath, 'r');
      closeSync(fd);
    });

    expect(leaked).toBe(0);
  });

  it('refuses an async thunk rather than measuring a window it does not own', (ctx) => {
    const probe = descriptorProbe();
    if (!probe.observable) ctx.skip(probe.reason ?? 'descriptor counting unavailable');

    // An async function satisfies `() => unknown`, so this is reachable from a
    // caller that compiles cleanly — the refusal has to be a runtime one.
    const asyncThunk = async (): Promise<void> => {
      await Promise.resolve();
    };

    expect(() => probe.leakedBy(asyncThunk)).toThrow(/synchronous/);
  });
});
