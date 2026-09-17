// Direct cover for `runHookFailOpen`, the single function all four Antigravity
// hook entries delegate the inverted fail-open contract to.
//
// Why this suite exists separately from the built-hook e2e: on THIS host,
// "fail open" is not the absence of output but the presence of specific bytes.
// Claude Code and Codex get every fault path for free — a crash, an unflushed
// pipe and a truncated write all converge on "said nothing", which those hosts
// read as no opinion. Antigravity reads all three as a `deny` on the tool call,
// so each one has to be shown PRODUCING a payload. The built-hook e2e proves
// that for one hook; this proves it for the wrapper the other three share.
//
// `runHookFailOpen` ends in `process.exit(0)`, so both process-level seams are
// stubbed: `exit` (which would otherwise kill the vitest worker) and
// `stdout.write` (the channel under assertion). `os.homedir()` is pointed at a
// throwaway home per case, so the fail-open count the wrapper writes lands
// there and never in the real one. Nothing else is faked — the real `emit`,
// the real race, the real watchdog and the real count all run.
//
// One consequence is worth stating because it cost a hole once. `driveWrapper`
// invokes the write callback IMMEDIATELY, which collapses "handed to the
// stream" and "reached the far end" into one instant — so no case using it can
// see whether `emit` awaits the flush, and a version that did not would pass
// every one of them. The `emit` describe block near the bottom withholds that
// callback instead, and is the only thing here covering that property.
import { mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { HookFailOpens } from '@akasecurity/plugin-sdk';
import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { emit, runHookFailOpen } from '../../src/hooks/shared.ts';

// The wrapper resolves the home it counts under through `os.homedir()`, as a
// shipped hook does. Each case sets `dir` to a throwaway home, and a lookup with
// none set throws rather than falling through to the real home. `refuse` makes
// the lookup throw on purpose: `os.homedir()` does that when the platform cannot
// name a home, and it is asked before the tally's own guard runs.
const osHome = vi.hoisted(() => ({ dir: '', refuse: false }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.refuse || osHome.dir === '') throw new Error('no home directory');
      return osHome.dir;
    },
  };
});

const ALLOW = { decision: 'allow' } as const;

/** The fail-open count this case's home holds, read from the path by hand. */
function failOpenTally(): HookFailOpens | null {
  return readHookFailOpens(join(osHome.dir, '.aka', 'data'));
}

interface WrapperRun {
  /** Every chunk handed to stdout, in order. */
  writes: string[];
  /** Exit codes passed to `process.exit`, in order. */
  exits: (number | undefined)[];
  /** The fail-open count on disk at the moment of each write, 0 for none. */
  countedAtWrite: number[];
}

/**
 * Drive the real wrapper with `process.exit` and `process.stdout.write`
 * captured.
 *
 * `exit` is stubbed to a no-op rather than a throw so the code AFTER it keeps
 * running: a body still pending when the watchdog wins must be given the chance
 * to write a second object, or the double-emit case below would pass because
 * the test stopped the clock rather than because the wrapper holds the line.
 *
 * `settle` lets a case wait for work the wrapper deliberately does not await.
 */
async function driveWrapper(
  main: () => Promise<unknown>,
  failOpen: unknown,
  watchdogMs?: number,
  settle: () => Promise<void> = () => Promise.resolve(),
): Promise<WrapperRun> {
  const writes: string[] = [];
  const exits: (number | undefined)[] = [];
  const countedAtWrite: number[] = [];

  // `process.exit` is declared to return `never`, which no stub can satisfy —
  // the cast is to a concrete signature rather than to `any`, so the argument
  // stays type-checked.
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((
    code?: string | number | null,
  ): undefined => {
    exits.push(typeof code === 'number' ? code : undefined);
    return undefined;
  }) as unknown as (code?: string | number | null) => never);

  // The real `emit` passes a completion callback and awaits it. A stub that
  // never invokes it would hang the wrapper forever, so it is always called.
  const writeSpy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array, cb?: unknown): boolean => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
      countedAtWrite.push(failOpenTally()?.failOpens ?? 0);
      if (typeof cb === 'function') (cb as () => void)();
      return true;
    });

  try {
    await runHookFailOpen(main, failOpen, watchdogMs);
    await settle();
  } finally {
    writeSpy.mockRestore();
    exitSpy.mockRestore();
  }
  return { writes, exits, countedAtWrite };
}

/**
 * The two things the host requires of every run, asserted together: exactly one
 * JSON object reached stdout, and the process exited 0.
 *
 * One object rather than "at least one" is the point — two concatenated objects
 * are not valid JSON, so a second write is a deny exactly like silence is.
 */
function soleDecision(run: WrapperRun): unknown {
  expect(run.writes).toHaveLength(1);
  expect(run.exits).toEqual([0]);
  return JSON.parse(run.writes[0] ?? '') as unknown;
}

beforeEach(() => {
  osHome.dir = mkdtempSync(join(tmpdir(), 'aka-agy-fail-open-wrapper-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(osHome.dir, { recursive: true, force: true });
  osHome.dir = '';
  osHome.refuse = false;
});

describe('runHookFailOpen — every path produces bytes, because silence is a deny here', () => {
  it('emits the fail-open payload when the body throws', async () => {
    const run = await driveWrapper(() => Promise.reject(new Error('boom')), ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
  });

  it('emits the fail-open payload when the body throws synchronously', async () => {
    // `main()` is called inside the try, so a body that throws before ever
    // returning a promise is caught by the same guard.
    const run = await driveWrapper(() => {
      throw new Error('sync boom');
    }, ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
  });

  it('emits the fail-open payload when the body declines to decide', async () => {
    const run = await driveWrapper(() => Promise.resolve(undefined), ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
  });

  it('emits the body’s own decision when it returns one', async () => {
    // The positive control. Without it a wrapper that ignored `main` entirely
    // and always wrote `failOpen` would satisfy every other case in this file.
    const deny = { decision: 'deny', reason: 'pointer' };
    const run = await driveWrapper(() => Promise.resolve(deny), ALLOW);
    expect(soleDecision(run)).toEqual(deny);
  });

  it('emits the fail-open payload when the body outruns the watchdog', async () => {
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    const run = await driveWrapper(
      () => pending.then(() => ({ decision: 'deny', reason: 'too late' })),
      ALLOW,
      5,
      // Let the losing body finish AFTER the wrapper has emitted and "exited",
      // then give its .then() a turn. This is the window in which a second
      // write would land.
      async () => {
        release();
        await pending;
        await new Promise((r) => setImmediate(r));
      },
    );
    // Still one object, and still the permissive one: the late decision is
    // dropped rather than appended. Two objects on one stdout would be invalid
    // JSON, which this host reads as a deny.
    expect(soleDecision(run)).toEqual(ALLOW);
  });

  it('survives a body that REJECTS after losing the race, without a second write', async () => {
    // The nastier sibling of the case above. A body that rejects late is the
    // one shape that could reach the host as a deny by a route the wrapper
    // never writes to: an unhandled rejection terminates the process non-zero,
    // and non-zero is a deny here regardless of what was already printed.
    //
    // It does not, because `Promise.race` leaves a handler attached to the
    // losing promise — settling it later is ignored rather than unhandled. That
    // is load-bearing and invisible in the source, so it is pinned here.
    let fail!: (e: Error) => void;
    const pending = new Promise<never>((_resolve, reject) => {
      fail = reject;
    });
    const seen: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      seen.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const run = await driveWrapper(
        () => pending,
        ALLOW,
        5,
        async () => {
          fail(new Error('late boom'));
          await pending.catch(() => undefined);
          // An unhandled rejection is reported on a later macrotask, so give the
          // loop two turns before concluding none fired.
          await new Promise((r) => setImmediate(r));
          await new Promise((r) => setImmediate(r));
        },
      );
      expect(soleDecision(run)).toEqual(ALLOW);
      expect(seen).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});

describe('runHookFailOpen — counts a failed body once, after its payload', () => {
  // `aka status` renders this count, so it has to mean a body that FAILED — one
  // that threw or outran the watchdog — and nothing else. The payload comes
  // first: the count is written only once the allow has been handed over, so
  // counting cannot delay it. And the count cannot throw: anything thrown after
  // `emit` would skip `process.exit(0)` and reject the entry's top-level await,
  // which exits non-zero, and non-zero is a deny on this host.

  it('counts a body that throws, after its payload is written', async () => {
    const before = Date.now();
    const run = await driveWrapper(() => Promise.reject(new Error('boom')), ALLOW);
    const after = Date.now();

    expect(soleDecision(run)).toEqual(ALLOW);
    // Nothing was on disk when the payload went out; the count landed after.
    expect(run.countedAtWrite).toEqual([0]);
    const tally = failOpenTally();
    expect(tally?.failOpens).toBe(1);
    expect(tally?.lastAtMs).toBeGreaterThanOrEqual(before);
    expect(tally?.lastAtMs).toBeLessThanOrEqual(after);
  });

  it('counts a body that throws synchronously', async () => {
    const run = await driveWrapper(() => {
      throw new Error('sync boom');
    }, ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
    expect(failOpenTally()?.failOpens).toBe(1);
  });

  it('counts a body that outruns the watchdog, after its payload is written', async () => {
    const run = await driveWrapper(() => new Promise<never>(() => undefined), ALLOW, 5);
    expect(soleDecision(run)).toEqual(ALLOW);
    expect(run.countedAtWrite).toEqual([0]);
    expect(failOpenTally()?.failOpens).toBe(1);
  });

  it('counts once when the body rejects after losing to the watchdog', async () => {
    // The run was counted when the watchdog won. The late rejection is the same
    // failure arriving a second time, and counting it too would count every
    // hook that hangs and then errors twice.
    let fail!: (e: Error) => void;
    const pending = new Promise<never>((_resolve, reject) => {
      fail = reject;
    });
    const run = await driveWrapper(
      () => pending,
      ALLOW,
      5,
      async () => {
        fail(new Error('late boom'));
        await pending.catch(() => undefined);
        await new Promise((r) => setImmediate(r));
      },
    );
    expect(soleDecision(run)).toEqual(ALLOW);
    expect(failOpenTally()?.failOpens).toBe(1);
  });

  it('does not count a body that returns its own decision', async () => {
    // A negative control: a wrapper that counted every run would satisfy each
    // counting case above.
    const deny = { decision: 'deny', reason: 'pointer' };
    const run = await driveWrapper(() => Promise.resolve(deny), ALLOW);
    expect(soleDecision(run)).toEqual(deny);
    expect(failOpenTally()).toBeNull();
  });

  it('does not count a body that declines to decide', async () => {
    // Declining is an ordinary answer — the event's own "carry on" — not a
    // failure, even though it writes the same payload a failure does.
    const run = await driveWrapper(() => Promise.resolve(undefined), ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
    expect(failOpenTally()).toBeNull();
  });

  it('still writes one payload and exits 0 when the home directory cannot be resolved', async () => {
    osHome.refuse = true;
    const run = await driveWrapper(() => Promise.reject(new Error('boom')), ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
  });
});

describe('runHookFailOpen — the limit the guarantee does not cover', () => {
  it('cannot preempt a body that blocks the thread, so the watchdog never fires', async () => {
    // This is the documented bound, pinned as behaviour rather than prose. A
    // synchronous body starves the timer: the watchdog is a `setTimeout` and
    // fires only when the loop gets a turn. Here the block outlasts the
    // watchdog by 20x and the body's OWN value is still what gets emitted —
    // proving the timer did not win the race it nominally should have.
    //
    // In production the host's 10s kill lands during such a block and NOTHING
    // is printed, which Antigravity reads as a deny. That cannot be reproduced
    // here without a real kill; what this pins is the mechanism underneath it.
    const blockMs = 40;
    const decided = { decision: 'deny', reason: 'blocked but still decided' };
    const run = await driveWrapper(
      () => {
        const until = Date.now() + blockMs;
        while (Date.now() < until) {
          /* block the loop the way a synchronous sqlite open does */
        }
        return Promise.resolve(decided);
      },
      ALLOW,
      2,
    );
    expect(soleDecision(run)).toEqual(decided);
  });
});

describe('emit — resolves on the FLUSH, not on handing bytes to the stream', () => {
  it('does not settle until stdout reports the write complete', async () => {
    // The property the `emit` callback exists for, and the one every other case
    // in this file is structurally blind to: they stub `write` to invoke its
    // callback immediately, so "handed to the stream" and "reached the far end"
    // collapse into the same instant and a version that never awaited the flush
    // would pass them all.
    //
    // Here the callback is withheld. An `emit` that resolves before it fires is
    // the regression: `process.exit` does not drain a pending pipe write, so a
    // payload past the ~64KB buffer would be truncated, and truncated JSON is
    // exactly as much a deny on this host as silence.
    let release: (() => void) | undefined;
    const writeSpy = vi
      .spyOn(process.stdout, 'write')
      .mockImplementation((_chunk: string | Uint8Array, cb?: unknown): boolean => {
        if (typeof cb === 'function') release = cb as () => void;
        // `false` is what a real stream returns once the buffer is full — the
        // condition under which the callback is genuinely deferred.
        return false;
      });

    try {
      let settled = false;
      const pending = emit({ decision: 'allow' }).then(() => {
        settled = true;
      });

      // Several turns are given deliberately: a microtask-only check would pass
      // against a version that resolved on the next tick.
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
      expect(release).toBeDefined();
      expect(settled).toBe(false);

      release?.();
      await pending;
      expect(settled).toBe(true);
    } finally {
      writeSpy.mockRestore();
    }
  });
});

describe('runHookFailOpen — the default watchdog leaves the host room to be beaten', () => {
  it('defaults to a watchdog strictly under every registered hook timeout', async () => {
    // The injectable parameter above must not be able to hide a regression in
    // the shipped value: a default at or past the host's own timeout would mean
    // the host kills the hook first and the watchdog never emits anything.
    const { default: hooks } = (await import('../../hooks.json', {
      with: { type: 'json' },
    })) as { default: unknown };

    const timeouts = collectTimeouts(hooks);
    expect(timeouts.length).toBeGreaterThan(0);
    for (const seconds of timeouts) {
      expect(DEFAULT_WATCHDOG_MS).toBeLessThan(seconds * 1000);
    }
  });
});

// Mirrors the module constant. Kept local rather than exported from src: the
// assertion above is about the shipped default being beatable, and reading it
// back out of the module under test would make that claim circular.
const DEFAULT_WATCHDOG_MS = 8_000;

/** Every `timeout` (seconds) registered anywhere in the hooks manifest. */
function collectTimeouts(node: unknown): number[] {
  if (Array.isArray(node)) return node.flatMap(collectTimeouts);
  if (typeof node !== 'object' || node === null) return [];
  const record = node as Record<string, unknown>;
  const here = typeof record.timeout === 'number' ? [record.timeout] : [];
  return [...here, ...Object.values(record).flatMap(collectTimeouts)];
}
