// Direct cover for `runHookFailOpen`, the wrapper this adapter's `preToolUse`
// entry delegates its fail-open contract to.
//
// What that contract IS, precisely, is the reason this suite exists separately
// from the built-hook e2e. On the Copilot CLI `preToolUse` is the one
// fail-closed event, but what fails closed is the EXIT CODE: the hooks
// reference denies on a non-zero exit other than 2, denies on exit 2, and
// documents timeouts as fail-open. Empty stdout is in none of those lists —
// the `preToolUse` decision table reads "Empty output uses default behavior".
// So each fault path has to be shown exiting 0 while writing NOTHING, and the
// thing that would be a defect is a payload appearing where no verdict was
// reached: on this host `permissionDecision: "allow"` pre-approves a call
// rather than declining to judge it.
//
// An absence assertion is worth nothing without something proving the harness
// can see a presence, so the `failOpen` seam is driven alongside every silence
// case: the same wrapper, handed a payload, writes exactly that payload. Delete
// the emit and the silence cases stay green while those go red.
//
// `runHookFailOpen` ends in `process.exit(0)`, so both process-level seams are
// stubbed: `exit` (which would otherwise kill the vitest worker) and
// `stdout.write` (the channel under assertion). Nothing else is faked — the
// real `emit`, the real race and the real watchdog all run.
//
// One consequence is worth stating because it cost a hole in the sibling once.
// `driveWrapper` invokes the write callback IMMEDIATELY, which collapses
// "handed to the stream" and "reached the far end" into one instant — so no
// case using it can see whether `emit` awaits the flush, and a version that did
// not would pass every one of them. The `emit` describe block near the bottom
// withholds that callback instead, and is the only thing here covering that
// property.
import { readFileSync } from 'node:fs';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { HookOutput } from '../../src/hooks/shared.ts';
import { emit, runHookFailOpen, WATCHDOG_MS, writeNotice } from '../../src/hooks/shared.ts';

/**
 * A payload for the `failOpen` seam.
 *
 * Deliberately NOT an allow, and deliberately not built by a helper this
 * adapter ships: no shipped hook passes a fail-open payload any more, and the
 * CLI shape can no longer even express an allow. This exists to prove the
 * wrapper emits what it is given — the positive control the silence cases need
 * — so any valid `HookOutput` serves, and a deny is the one shape whose
 * appearance in the wrong place would be unmistakable.
 */
const SEAM_PAYLOAD: HookOutput = {
  permissionDecision: 'deny',
  permissionDecisionReason: 'seam',
};

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
  failOpen?: HookOutput,
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
 * The two things the host requires of a run that DID decide: exactly one JSON
 * object reached stdout, and the process exited 0.
 *
 * One object rather than "at least one" is the point — two concatenated objects
 * are not valid JSON, so a second write loses the verdict entirely. Exit 0
 * rather than "not 2" for the same reason: on the CLI a non-zero exit is a deny
 * outright, and under VS Code exit 2 is the block channel.
 */
function soleDecision(run: WrapperRun): unknown {
  expect(run.writes).toHaveLength(1);
  expect(run.exits).toEqual([0]);
  return JSON.parse(run.writes[0] ?? '') as unknown;
}

/**
 * The shape of a run that reached no verdict: nothing on stdout, exit 0.
 *
 * `writes` is asserted as the empty ARRAY rather than by length so a failure
 * prints what was written — the useful half when this goes red, since the whole
 * question is which payload crept back in.
 */
function noDecision(run: WrapperRun): void {
  expect(run.writes).toEqual([]);
  expect(run.exits).toEqual([0]);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('runHookFailOpen — a path with no verdict writes nothing and still exits 0', () => {
  it('writes nothing when the body throws', async () => {
    noDecision(await driveWrapper(() => Promise.reject(new Error('boom'))));
  });

  it('writes nothing when the body throws synchronously', async () => {
    // `main()` is called inside the try, so a body that throws before ever
    // returning a promise is caught by the same guard.
    noDecision(
      await driveWrapper(() => {
        throw new Error('sync boom');
      }),
    );
  });

  it('writes nothing when the body declines to decide', async () => {
    noDecision(await driveWrapper(() => Promise.resolve(undefined)));
  });

  it('writes nothing when the body outruns the watchdog', async () => {
    // The timeout path, which the host itself documents as fail-open — so the
    // wrapper has nothing to add here beyond not inventing a verdict.
    const run = await driveWrapper(() => new Promise<undefined>(() => undefined), undefined, 5);
    noDecision(run);
  });

  it('emits the body’s own decision when it returns one', async () => {
    // The positive control for the whole block. Without it, a wrapper that had
    // lost its `emit` call entirely would satisfy every silence case above.
    const deny: HookOutput = { permissionDecision: 'deny', permissionDecisionReason: 'pointer' };
    const run = await driveWrapper(() => Promise.resolve(deny));
    expect(soleDecision(run)).toEqual(deny);
  });

  it('emits a VS Code payload unchanged, so the wrapper stays dialect-blind', async () => {
    // The second positive control, and it is not redundant: it is the only
    // thing here proving a nested payload survives the wrapper as itself. A
    // version that re-shaped output on its way to `emit` would pass the flat
    // case above.
    const allow: HookOutput = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: { command: 'echo redacted' },
      },
      systemMessage: 'AKA redacted sensitive content',
    };
    const run = await driveWrapper(() => Promise.resolve(allow));
    expect(soleDecision(run)).toEqual(allow);
  });
});

describe('runHookFailOpen — the `failOpen` seam, which no shipped hook uses', () => {
  it('writes the payload it was given when the body throws', async () => {
    const run = await driveWrapper(() => Promise.reject(new Error('boom')), SEAM_PAYLOAD);
    expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
  });

  it('writes the payload it was given when the body declines', async () => {
    const run = await driveWrapper(() => Promise.resolve(undefined), SEAM_PAYLOAD);
    expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
  });

  it('prefers the body’s decision over the payload it was given', async () => {
    // Ordering, not just presence: the seam is a FALLBACK, so a wrapper that
    // wrote it unconditionally would break every real decision.
    const deny: HookOutput = { permissionDecision: 'deny', permissionDecisionReason: 'real' };
    const run = await driveWrapper(() => Promise.resolve(deny), SEAM_PAYLOAD);
    expect(soleDecision(run)).toEqual(deny);
  });

  it('writes no placeholder object when it is omitted', async () => {
    // The distinction the guard in `runHookFailOpen` exists for: `{}` is a
    // payload the host PARSES — the reference merges stdout JSON into the deny
    // on exit 2 — so an empty object is never equivalent to writing nothing.
    const run = await driveWrapper(() => Promise.resolve(undefined));
    expect(run.writes).toEqual([]);
    expect(run.writes.join('')).not.toContain('{');
  });
});

describe('runHookFailOpen — a late body must not append a second write', () => {
  it('drops a decision that arrives after the watchdog won', async () => {
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
      SEAM_PAYLOAD,
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
    // Still exactly one object, and still the one the watchdog chose: the late
    // decision is dropped rather than appended. Two objects on one stdout are
    // not valid JSON, so an appended verdict destroys the first one too.
    //
    // Driven through the seam rather than through silence on purpose: with no
    // payload the run writes nothing, and "nothing, then nothing" would hold
    // whether or not the late write was suppressed.
    expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
  });

  it('survives a body that REJECTS after losing the race, without a second write', async () => {
    // The nastier sibling of the case above. A body that rejects late is the
    // one shape that could reach the host as a deny by a route the wrapper
    // never writes to: an unhandled rejection terminates the process non-zero,
    // and non-zero is a deny on `preToolUse` regardless of what was already
    // printed.
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
        SEAM_PAYLOAD,
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
      expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
      expect(seen).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
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
    // In production the host's 30s kill lands during such a block and NOTHING
    // is printed. That cannot be reproduced here without a real kill; what this
    // pins is the mechanism underneath it.
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
      SEAM_PAYLOAD,
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
    // payload past the ~64KB buffer would be truncated, and truncated JSON is a
    // worse answer than either verdict.
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
      const pending = emit(SEAM_PAYLOAD).then(() => {
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

describe('writeNotice — the channel a verdict cannot share', () => {
  it('writes the message with a trailing newline', () => {
    // The newline is the convention this module chose and the opposite of
    // `storeRedirectedMessage`'s, which carries its own — so it is asserted
    // rather than left to the caller to discover.
    const written: string[] = [];
    writeNotice('AKA flagged sensitive content', (text) => {
      written.push(text);
    });
    expect(written).toEqual(['AKA flagged sensitive content\n']);
  });

  it('swallows a writer that throws, because a throw here would DENY', () => {
    // The branch nothing else reaches, and the reason it exists: this runs
    // inside `main()`, so an escaping error would reach the wrapper's catch —
    // or, on the store-unavailable path, leave the hook exiting non-zero, which
    // on the Copilot CLI is a deny. Losing the notice is the lesser outcome.
    expect(() => {
      writeNotice('boom', () => {
        throw new Error('EPIPE');
      });
    }).not.toThrow();
  });

  it('really does write through the default path', () => {
    // The control on both cases above: they inject a writer, so neither can see
    // that the default is wired to stderr at all. A `writeNotice` whose default
    // was a no-op would pass them and silently drop every shipped notice.
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      writeNotice('to stderr');
      expect(spy).toHaveBeenCalledWith('to stderr\n');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('the CLI verdict type cannot express an allow', () => {
  it('is a compile error, so the property is held by tsc rather than by a case', () => {
    // `CliPermissionDecisionOutput.permissionDecision` is `'deny'` alone. The
    // line below is what a regression looks like, kept as a `@ts-expect-error`
    // so it is `typecheck` that fails when the union is widened back — a
    // runtime assertion could not see a type at all.
    //
    // `@ts-expect-error` is itself the assertion: it FAILS when the error stops
    // occurring, so this cannot rot into a comment about a type that now
    // permits an allow.
    // @ts-expect-error an allow on the CLI dialect must not typecheck
    const widened: HookOutput = { permissionDecision: 'allow' };
    // Referenced so the binding is not merely unused, and asserted so the case
    // carries a runtime expectation too.
    expect(widened).toEqual({ permissionDecision: 'allow' });
  });

  it('still spells the VS Code allow, which that host needs for a rewrite', () => {
    // The other half, and the reason this is a narrowing rather than a ban:
    // VS Code carries `updatedInput` only alongside an `allow`, so removing the
    // verdict there would remove the rewrite channel with it.
    const allow: HookOutput = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: { command: 'echo ok' },
      },
    };
    expect(allow.hookSpecificOutput.permissionDecision).toBe('allow');
  });
});

describe('WATCHDOG_MS — the shipped default has to be beatable', () => {
  it('sits strictly under the host timeout this adapter registers', () => {
    // The injectable parameter above must not hide a regression in the shipped
    // value: a default at or past the host's own timeout means the host kills
    // the hook first and the watchdog never emits anything at all.
    //
    // Read out of the manifest rather than restated, so a `timeoutSec` lowered
    // there without moving the watchdog is a failure here. (`hooks-manifest.
    // test.ts` asserts the same relation from the other side; this is the half
    // that belongs next to the constant.)
    const timeouts = collectTimeouts(
      JSON.parse(readFileSync(new URL('../../hooks.json', import.meta.url), 'utf8')),
    );
    expect(timeouts.length).toBeGreaterThan(0);
    for (const seconds of timeouts) expect(WATCHDOG_MS).toBeLessThan(seconds * 1000);
    // And a positive control on the other side: a watchdog of nearly nothing
    // would satisfy the bound above while firing before any real body could
    // finish, which is a hook that never decides anything.
    expect(WATCHDOG_MS).toBeGreaterThan(10 * 1000);
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
