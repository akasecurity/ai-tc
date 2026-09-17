// Direct cover for `runHookFailOpen`, which the `preToolUse` entry delegates
// its whole contract to.
//
// Why this suite exists separately from the built-hook e2e: on THIS event,
// "fail open" is not the absence of output but the presence of specific bytes.
// Copilot CLI reads a `preToolUse` hook that exits non-zero or crashes as a
// DENY, and its reading of exit-0-with-empty-stdout has not been observed on a
// live install — so silence is at best unproven and at worst a block. Every
// fault path therefore has to be shown PRODUCING a payload.
//
// `runHookFailOpen` ends in `process.exit(0)`, so both process-level seams are
// stubbed: `exit` (which would otherwise kill the vitest worker) and
// `stdout.write` (the channel under assertion). Nothing else is faked — the
// real `emit`, the real race and the real watchdog all run.
//
// One consequence is worth stating because it is easy to lose. `driveWrapper`
// invokes the write callback IMMEDIATELY, which collapses "handed to the
// stream" and "reached the far end" into one instant — so no case using it can
// see whether `emit` awaits the flush, and a version that did not would pass
// every one of them. The `emit` describe block near the bottom withholds that
// callback instead, and is the only thing here covering that property.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { HookOutput } from '../../src/hooks/shared.ts';
import { allowPayload, emit, runHookFailOpen, WATCHDOG_MS } from '../../src/hooks/shared.ts';

const ALLOW = allowPayload('cli');

interface WrapperRun {
  /** Every chunk handed to stdout, in order. */
  writes: string[];
  /** Exit codes passed to `process.exit`, in order. */
  exits: (number | undefined)[];
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
  main: () => Promise<HookOutput | undefined>,
  failOpen: HookOutput,
  watchdogMs?: number,
  settle: () => Promise<void> = () => Promise.resolve(),
): Promise<WrapperRun> {
  const writes: string[] = [];
  const exits: (number | undefined)[] = [];

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
  return { writes, exits };
}

/**
 * The two things the host requires of every run, asserted together: exactly one
 * JSON object reached stdout, and the process exited 0.
 *
 * One object rather than "at least one" is the point — two concatenated objects
 * are not valid JSON, so a second write is read exactly as silence is.
 */
function soleDecision(run: WrapperRun): unknown {
  expect(run.writes).toHaveLength(1);
  expect(run.exits).toEqual([0]);
  return JSON.parse(run.writes[0] ?? '') as unknown;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('runHookFailOpen — every path produces bytes', () => {
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
    // The unknown-tool fast path and the unparseable-stdin path both land here.
    const run = await driveWrapper(() => Promise.resolve(undefined), ALLOW);
    expect(soleDecision(run)).toEqual(ALLOW);
  });

  it('emits the body’s own decision when it returns one', async () => {
    // The positive control. Without it a wrapper that ignored `main` entirely
    // and always wrote `failOpen` would satisfy every other case in this file —
    // and would be a plugin that can never block anything.
    const deny: HookOutput = { permissionDecision: 'deny', permissionDecisionReason: 'pointer' };
    const run = await driveWrapper(() => Promise.resolve(deny), ALLOW);
    expect(soleDecision(run)).toEqual(deny);
  });

  it('emits the fail-open payload when the body outruns the watchdog', async () => {
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    const run = await driveWrapper(
      () =>
        pending.then((): HookOutput => ({
          permissionDecision: 'deny',
          permissionDecisionReason: 'too late',
        })),
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
    // dropped rather than appended.
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
          // An unhandled rejection is reported on a later macrotask, so give
          // the loop two turns before concluding none fired.
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

describe('runHookFailOpen — the limit the guarantee does not cover', () => {
  it('cannot preempt a body that blocks the thread, so the watchdog never fires', async () => {
    // The documented bound, pinned as behaviour rather than prose. A
    // synchronous body starves the timer: the watchdog is a `setTimeout` and
    // fires only when the loop gets a turn. Here the block outlasts the
    // watchdog by 20x and the body's OWN value is still what gets emitted —
    // proving the timer did not win the race it nominally should have.
    //
    // In production the host's 30s kill lands during such a block and NOTHING
    // is printed. That cannot be reproduced here without a real kill; what this
    // pins is the mechanism underneath it, and why a longer timer is never the
    // fix — only moving the work off the thread is.
    const blockMs = 40;
    const decided: HookOutput = {
      permissionDecision: 'deny',
      permissionDecisionReason: 'blocked but still decided',
    };
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
    // payload past the ~64KB buffer would be truncated — and truncated JSON on
    // `preToolUse` is read exactly as silence is.
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
      const pending = emit(ALLOW).then(() => {
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

describe('allowPayload — the explicit allow, per dialect', () => {
  it('is a top-level permissionDecision on the CLI', () => {
    expect(allowPayload('cli')).toEqual({ permissionDecision: 'allow' });
  });

  it('is a hookSpecificOutput on VS Code', () => {
    expect(allowPayload('vscode')).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: {},
      },
    });
  });

  it('returns a fresh object each call', () => {
    // Not a shared frozen constant: `emit` serializes whatever it is handed,
    // and one object shared between two hosts invites a mutation that reaches
    // both.
    expect(allowPayload('cli')).not.toBe(allowPayload('cli'));
  });
});

describe('the shipped watchdog default', () => {
  it('is strictly under every timeout the manifest registers', () => {
    // Same claim the manifest suite makes, made from the other side: there the
    // manifest is checked against the constant, here the constant is checked
    // against the manifest. Both are cheap and neither subsumes the other — a
    // manifest that registered no timeout at all would satisfy the loop there
    // vacuously, which the count assertion below refuses.
    const PLUGIN_ROOT = fileURLToPath(new URL('../../', import.meta.url));
    const manifest = JSON.parse(readFileSync(`${PLUGIN_ROOT}hooks.json`, 'utf8')) as unknown;
    const timeouts = collectTimeouts(manifest);
    expect(timeouts.length).toBeGreaterThan(0);
    for (const seconds of timeouts) expect(WATCHDOG_MS).toBeLessThan(seconds * 1000);
  });
});

/** Every `timeoutSec` registered anywhere in the hooks manifest. */
function collectTimeouts(node: unknown): number[] {
  if (Array.isArray(node)) return node.flatMap(collectTimeouts);
  if (typeof node !== 'object' || node === null) return [];
  const record = node as Record<string, unknown>;
  const here = typeof record.timeoutSec === 'number' ? [record.timeoutSec] : [];
  return [...here, ...Object.values(record).flatMap(collectTimeouts)];
}
