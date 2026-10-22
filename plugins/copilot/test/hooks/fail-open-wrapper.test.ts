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
import {
  emit,
  noticeWriter,
  progressLine,
  runHookFailOpen,
  takeQueuedProgress,
  WATCHDOG_MS,
  writeNotice,
} from '../../src/hooks/shared.ts';
import { readCliStdout } from '../helpers/cli-stdout.ts';

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
  /** How many times the wrapper asked for a fail-open to be counted. */
  counts: number;
  /** Every write, count and exit, in the order they happened. */
  order: ('write' | 'count' | 'exit')[];
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
 *
 * The fail-open counter is ALWAYS injected: the shipped default starts a real
 * process, and every case here that drives a failure would otherwise spawn one
 * from the vitest worker.
 */
async function driveWrapper(
  main: () => Promise<HookOutput | undefined>,
  failOpen?: HookOutput,
  watchdogMs?: number,
  settle: () => Promise<void> = () => Promise.resolve(),
): Promise<WrapperRun> {
  const writes: string[] = [];
  const exits: (number | undefined)[] = [];
  const order: WrapperRun['order'] = [];
  let counts = 0;

  // `process.exit` is declared to return `never`, which no stub can satisfy —
  // the cast is to a concrete signature rather than to `any`, so the argument
  // stays type-checked.
  const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((
    code?: string | number | null,
  ): undefined => {
    exits.push(typeof code === 'number' ? code : undefined);
    order.push('exit');
    return undefined;
  }) as unknown as (code?: string | number | null) => never);

  // The real `emit` passes a completion callback and awaits it. A stub that
  // never invokes it would hang the wrapper forever, so it is always called.
  const writeSpy = vi
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: string | Uint8Array, cb?: unknown): boolean => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
      order.push('write');
      if (typeof cb === 'function') (cb as () => void)();
      return true;
    });

  // `emit` leaves one stdout 'error' listener behind per write, by design: a
  // real hook exits right after. A worker that drives many runs would cross
  // Node's leak warning, so the ones a run added are removed when it ends.
  const listenersBefore = new Set(process.stdout.listeners('error'));

  try {
    await runHookFailOpen(main, failOpen, watchdogMs, () => {
      counts += 1;
      order.push('count');
    });
    await settle();
  } finally {
    writeSpy.mockRestore();
    exitSpy.mockRestore();
    for (const listener of process.stdout.listeners('error')) {
      if (!listenersBefore.has(listener)) {
        process.stdout.off('error', listener as (...args: unknown[]) => void);
      }
    }
  }
  return { writes, exits, counts, order };
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

describe('runHookFailOpen — a failure is counted once, after the write and before the exit', () => {
  // A failed body writes nothing and exits 0, which is byte-for-byte a clean
  // call, so the count is the only trace `aka status` has that this hook is not
  // scanning. Each failure path is driven twice: silent, as every shipped hook
  // runs, and through the seam, because "count, then exit" holds whether or not
  // the count waited for the write when nothing is written — only a payload can
  // show the count landing AFTER it.
  const throwsAsync = (): Promise<HookOutput | undefined> => Promise.reject(new Error('boom'));
  const throwsSync = (): Promise<HookOutput | undefined> => {
    throw new Error('sync boom');
  };
  const neverSettles = (): Promise<HookOutput | undefined> => new Promise(() => undefined);

  it.each([
    ['throws', throwsAsync, undefined],
    ['throws synchronously', throwsSync, undefined],
    ['outruns the watchdog', neverSettles, 5],
  ] as const)('counts a body that %s, writing nothing first', async (_name, main, watchdogMs) => {
    const run = await driveWrapper(main, undefined, watchdogMs);
    expect(run.writes).toEqual([]);
    expect(run.counts).toBe(1);
    expect(run.order).toEqual(['count', 'exit']);
    expect(run.exits).toEqual([0]);
  });

  it.each([
    ['throws', throwsAsync, undefined],
    ['throws synchronously', throwsSync, undefined],
    ['outruns the watchdog', neverSettles, 5],
  ] as const)(
    'counts a body that %s only once its payload is written',
    async (_name, main, watchdogMs) => {
      const run = await driveWrapper(main, SEAM_PAYLOAD, watchdogMs);
      expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
      expect(run.counts).toBe(1);
      expect(run.order).toEqual(['write', 'count', 'exit']);
    },
  );

  it('counts a body that rejects after losing the race once, not twice', async () => {
    let fail!: (e: Error) => void;
    const pending = new Promise<never>((_resolve, reject) => {
      fail = reject;
    });
    const run = await driveWrapper(
      () => pending,
      SEAM_PAYLOAD,
      5,
      async () => {
        fail(new Error('late boom'));
        await pending.catch(() => undefined);
        await new Promise((r) => setImmediate(r));
      },
    );
    expect(soleDecision(run)).toEqual(SEAM_PAYLOAD);
    expect(run.counts).toBe(1);
    expect(run.order).toEqual(['write', 'count', 'exit']);
  });

  it('does not count a body that returns its own decision', async () => {
    const deny: HookOutput = { permissionDecision: 'deny', permissionDecisionReason: 'pointer' };
    const run = await driveWrapper(() => Promise.resolve(deny));
    expect(soleDecision(run)).toEqual(deny);
    expect(run.counts).toBe(0);
    expect(run.order).toEqual(['write', 'exit']);
  });

  it('does not count a body that declines to decide', async () => {
    const silent = await driveWrapper(() => Promise.resolve(undefined));
    expect(silent.counts).toBe(0);
    expect(silent.order).toEqual(['exit']);

    const seamed = await driveWrapper(() => Promise.resolve(undefined), SEAM_PAYLOAD);
    expect(seamed.counts).toBe(0);
    expect(seamed.order).toEqual(['write', 'exit']);
  });

  it('still exits 0 when the counter itself throws', async () => {
    // The default never throws, but the wrapper does not rely on that: a throw
    // here would skip the exit and reject the entry's top-level await, which
    // exits non-zero — a deny on the CLI's `preToolUse`.
    const exits: (number | undefined)[] = [];
    vi.spyOn(process, 'exit').mockImplementation(((code?: string | number | null): undefined => {
      exits.push(typeof code === 'number' ? code : undefined);
      return undefined;
    }) as unknown as (code?: string | number | null) => never);
    let asked = 0;
    await expect(
      runHookFailOpen(
        () => Promise.reject(new Error('boom')),
        undefined,
        undefined,
        () => {
          asked += 1;
          throw new Error('cannot count');
        },
      ),
    ).resolves.toBeUndefined();
    expect(asked).toBe(1);
    expect(exits).toEqual([0]);
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
  // Every case drains the queue first and last: it is module state, and a
  // notice another case queued would otherwise read as this case's.
  afterEach(() => {
    takeQueuedProgress();
  });

  it('writes the message to stderr with a trailing newline', () => {
    // The newline is the convention this module chose and the opposite of
    // `storeRedirectedMessage`'s, which carries its own — so it is asserted
    // rather than left to the caller to discover.
    takeQueuedProgress();
    const written: string[] = [];
    writeNotice('AKA flagged sensitive content', 'vscode', (text) => {
      written.push(text);
    });
    expect(written).toEqual(['AKA flagged sensitive content\n']);
  });

  it('queues a progress line on the CLI dialect, and only there', () => {
    // The CLI's stderr was recorded reaching only its debug log, so the copy
    // the user can see is the progress line. VS Code gets none: its harness
    // documents no progress line, and an extra one beside a decision there
    // could cost the decision.
    takeQueuedProgress();
    writeNotice('cli notice', 'cli', () => undefined);
    writeNotice('vscode notice', 'vscode', () => undefined);
    writeNotice('no dialect', undefined, () => undefined);
    expect(takeQueuedProgress()).toEqual(['cli notice']);
    // Taking empties the queue, so a notice is written once.
    expect(takeQueuedProgress()).toEqual([]);
  });

  it('swallows a writer that throws, because a throw here would DENY', () => {
    // The branch nothing else reaches, and the reason it exists: this runs
    // inside `main()`, so an escaping error would reach the wrapper's catch —
    // or, on the store-unavailable path, leave the hook exiting non-zero, which
    // on the Copilot CLI is a deny. Losing the notice is the lesser outcome.
    takeQueuedProgress();
    expect(() => {
      writeNotice('boom', 'cli', () => {
        throw new Error('EPIPE');
      });
    }).not.toThrow();
    // And a stderr that throws does not cost the copy the user can see.
    expect(takeQueuedProgress()).toEqual(['boom']);
  });

  it('really does write through the default path', () => {
    // The control on the cases above: they inject a writer, so none can see
    // that the default is wired to stderr at all. A `writeNotice` whose default
    // was a no-op would pass them and silently drop every shipped notice.
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      writeNotice('to stderr', 'cli');
      expect(spy).toHaveBeenCalledWith('to stderr\n');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('noticeWriter — self-terminated text, routed like a notice', () => {
  afterEach(() => {
    takeQueuedProgress();
  });

  it('writes the text as given to stderr and queues it without its newline on the CLI', () => {
    takeQueuedProgress();
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      noticeWriter('cli')('store redirected\n');
      noticeWriter('vscode')('not queued\n');
      expect(spy.mock.calls.map((call) => call[0])).toEqual(['store redirected\n', 'not queued\n']);
    } finally {
      spy.mockRestore();
    }
    expect(takeQueuedProgress()).toEqual(['store redirected']);
  });
});

describe('runHookFailOpen — queued notices become progress lines on stdout', () => {
  afterEach(() => {
    takeQueuedProgress();
  });

  it('writes them ahead of the decision, in ONE write the host can still parse', async () => {
    takeQueuedProgress();
    const deny: HookOutput = { permissionDecision: 'deny', permissionDecisionReason: 'r' };
    const run = await driveWrapper(() => {
      writeNotice('first', 'cli', () => undefined);
      writeNotice('second', 'cli', () => undefined);
      return Promise.resolve(deny);
    });
    // One write, so an exit cannot land between the notices and the verdict.
    expect(run.writes).toHaveLength(1);
    // Ahead of the object, as the reference writes it ("before writing the
    // final output"): the host strips a progress line wherever it sits, but
    // only the documented order is one anybody has said works.
    expect(run.writes[0]).toBe(
      `${progressLine('first')}${progressLine('second')}${JSON.stringify(deny)}`,
    );
    expect(run.exits).toEqual([0]);
    expect(readCliStdout(run.writes[0] ?? '')).toEqual({
      progress: ['first', 'second'],
      rest: JSON.stringify(deny),
      output: deny,
    });
  });

  it('writes them with no decision, which leaves the hook output EMPTY', async () => {
    // The warn path on the CLI: the user is told, and the host still reads no
    // verdict, so the call goes to its own permission flow exactly as before.
    takeQueuedProgress();
    const run = await driveWrapper(() => {
      writeNotice('AKA flagged sensitive content', 'cli', () => undefined);
      return Promise.resolve(undefined);
    });
    expect(run.exits).toEqual([0]);
    expect(run.writes).toEqual([progressLine('AKA flagged sensitive content')]);
    const read = readCliStdout(run.writes.join(''));
    expect(read.progress).toEqual(['AKA flagged sensitive content']);
    expect(read.output).toBeUndefined();
  });

  it('writes nothing for a VS Code notice, whose payload carries its own', async () => {
    // The control on the case above: the progress write is the CLI dialect's,
    // so a body that only wrote a VS Code-dialect notice leaves stdout empty.
    takeQueuedProgress();
    noDecision(
      await driveWrapper(() => {
        writeNotice('vscode notice', 'vscode', () => undefined);
        return Promise.resolve(undefined);
      }),
    );
  });

  it('still writes what was queued when the watchdog fires', async () => {
    // A notice already produced is worth showing even when the body then
    // stalls; it is not a verdict, so it cannot turn the timeout into one.
    takeQueuedProgress();
    const run = await driveWrapper(
      () => {
        writeNotice('before the stall', 'cli', () => undefined);
        return new Promise<undefined>(() => undefined);
      },
      undefined,
      5,
    );
    expect(run.exits).toEqual([0]);
    expect(run.writes).toEqual([progressLine('before the stall')]);
    expect(run.counts).toBe(1);
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
