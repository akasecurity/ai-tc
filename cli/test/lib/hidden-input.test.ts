import { EventEmitter } from 'node:events';
import { ReadStream } from 'node:tty';

import { describe, expect, it } from 'vitest';

import type { TerminalIo } from '../../src/lib/prompter.ts';
import { terminalPrompter } from '../../src/lib/prompter.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// A high-entropy stand-in for a secret typed at the prompt. It matches no
// detection rule and looks like nothing in particular — a credential-shaped
// literal has no place in a public repo, and an English phrase collides with
// ordinary output text and would blunt the echo check below.
const TYPED = 'q7XbR2mV9kTz4Ln8';

// -------------------------------------------------------------------------
// A scripted terminal
// -------------------------------------------------------------------------

/**
 * A stand-in for `process.stdin` as a TTY. It models the members askHidden
 * uses, and — the reason it is hand-rolled rather than a PassThrough — it
 * RECORDS the raw-mode transitions in order. A stuck raw mode is invisible to
 * an assertion on the returned value: the promise resolves correctly either
 * way, and what is left behind is a shell with echo disabled.
 */
class FakeTty extends EventEmitter {
  // Plain boolean, not `true as const`: the isInteractive case has to vary it,
  // and a literal type forces that assignment through a cast which would then
  // stop type-checking the field name.
  isTTY = true;
  rawModeCalls: boolean[] = [];
  resumeCount = 0;
  pauseCount = 0;
  /** When set, setRawMode(false) throws — the hangup case. */
  failRestore = false;

  setRawMode(mode: boolean): this {
    this.rawModeCalls.push(mode);
    if (!mode && this.failRestore) throw new Error('ENOTTY');
    return this;
  }
  resume(): this {
    this.resumeCount += 1;
    return this;
  }
  pause(): this {
    this.pauseCount += 1;
    return this;
  }
  /** Deliver keystrokes the way a terminal does — one chunk. */
  type(text: string): void {
    this.emit('data', Buffer.from(text, 'utf8'));
  }
  get rawModeNow(): boolean | undefined {
    return this.rawModeCalls.at(-1);
  }
}

class FakeOut extends EventEmitter {
  isTTY = true;
  written = '';
  write(text: string): boolean {
    this.written += text;
    return true;
  }
}

/**
 * A re-raise, plus the terminal state AT THE MOMENT it happened.
 *
 * Recording the state as the raise goes past is the whole point. The real hook
 * is `process.kill(process.pid, sig)` with the signal's default disposition, so
 * it is a point of no return: whatever has not been restored by then is never
 * restored. A fake that only appended the signal name reads the same for both
 * orderings, because the assertion then runs after the handler has finished and
 * both statements have executed either way.
 */
interface RaiseRecord {
  signal: NodeJS.Signals;
  rawModeAtRaise: boolean | undefined;
  dataListenersAtRaise: number;
}

interface Harness {
  io: TerminalIo;
  tty: FakeTty;
  out: FakeOut;
  err: FakeOut;
  /** Signals registered right now, in registration order. */
  registered: () => NodeJS.Signals[];
  /** Every re-raise, with the terminal state as it was when it happened. */
  raised: () => RaiseRecord[];
  /** Invoke the handler for `signal` the way the process would. */
  deliver: (signal: NodeJS.Signals) => void;
}

function harness(): Harness {
  const tty = new FakeTty();
  const out = new FakeOut();
  const err = new FakeOut();
  const handlers = new Map<NodeJS.Signals, (signal: NodeJS.Signals) => void>();
  const order: NodeJS.Signals[] = [];
  const raised: RaiseRecord[] = [];

  const io: TerminalIo = {
    input: tty as unknown as NodeJS.ReadStream,
    output: out as unknown as NodeJS.WriteStream,
    errorOutput: err as unknown as NodeJS.WriteStream,
    signals: {
      once: (signal, handler) => {
        handlers.set(signal, handler);
        order.push(signal);
      },
      off: (signal) => {
        handlers.delete(signal);
      },
      // Recorded rather than performed — the real hook would take the test
      // runner down with it — and recorded WITH the state it interrupted, so
      // the ordering is observable rather than inferred after the fact.
      raise: (signal) => {
        raised.push({
          signal,
          rawModeAtRaise: tty.rawModeNow,
          dataListenersAtRaise: tty.listenerCount('data'),
        });
      },
    },
  };

  return {
    io,
    tty,
    out,
    err,
    registered: () => order.filter((sig) => handlers.has(sig)),
    raised: () => raised,
    deliver: (signal) => {
      const handler = handlers.get(signal);
      if (handler === undefined) throw new Error(`no handler registered for ${signal}`);
      handler(signal);
    },
  };
}

// -------------------------------------------------------------------------
// The raw-mode lifecycle
// -------------------------------------------------------------------------

// Every case here runs on every platform. That is the point rather than a
// compromise: no CI runner has a TTY on any OS, so a suite gated on a real
// terminal would run nowhere, and the property under test — raw mode goes on
// once and comes off on every exit — is the same property whichever tty layer
// is underneath. What only a real Windows runner adds is Node's own conio raw
// mode and the signal names it accepts, pinned separately below.
describe('askHidden raw-mode lifecycle', () => {
  it('turns raw mode on before reading and off again on submit', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    expect(h.tty.rawModeCalls).toEqual([true]);
    expect(h.tty.resumeCount).toBe(1);

    h.tty.type(`${TYPED}\r`);
    await expect(pending).resolves.toBe(TYPED);

    expect(h.tty.rawModeCalls).toEqual([true, false]);
    expect(h.tty.pauseCount).toBe(1);
  });

  it('turns raw mode off on cancel too', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type(`${TYPED}\u0003`); // Ctrl+C
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(h.tty.rawModeNow).toBe(false);
  });

  it('turns raw mode off when the stream errors', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.emit('error', new Error('EIO'));
    await expect(pending).rejects.toThrow(/EIO/);
    expect(h.tty.rawModeNow).toBe(false);
  });

  it('restores once, not once per event', async () => {
    // `restore` is one-shot. Without the latch, a stream error followed by the
    // keystrokes already queued behind it runs the teardown twice:
    // setRawMode(false) on a torn-down tty, a second '\n' printed over the
    // caller's next line, and a second settle on an already-settled promise.
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.emit('error', new Error('EIO'));
    await expect(pending).rejects.toThrow(/EIO/);

    // The data listener went with the teardown, so this reaches nothing — which
    // is the property. It is data rather than a second 'error' because an
    // EventEmitter with no 'error' listener throws, and that throw would be the
    // fake's behaviour under test rather than askHidden's.
    h.tty.type('more\r');

    expect(h.tty.rawModeCalls).toEqual([true, false]);
    expect(h.tty.pauseCount).toBe(1);
    expect(h.out.written).toBe('Value: \n');
  });

  it('still resolves when restoring raw mode throws (the hangup case)', async () => {
    // A tty that has gone away rejects setRawMode(false). Echo died with it, so
    // there is nothing left to restore — but the throw must not escape and
    // leave the caller's promise hanging forever.
    const h = harness();
    h.tty.failRestore = true;
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type(`${TYPED}\r`);
    await expect(pending).resolves.toBe(TYPED);
    expect(h.tty.pauseCount).toBe(1);
  });

  it('leaves no data or error listener on the stream', async () => {
    // The prompter is called more than once in a session (`aka exception` asks
    // twice). A leaked 'data' listener means the next prompt's keystrokes are
    // also fed to this one's dead reducer.
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    expect(h.tty.listenerCount('data')).toBe(1);
    h.tty.type(`${TYPED}\r`);
    await pending;
    expect(h.tty.listenerCount('data')).toBe(0);
    expect(h.tty.listenerCount('error')).toBe(0);
  });
});

// -------------------------------------------------------------------------
// What the terminal is allowed to show
// -------------------------------------------------------------------------

describe('askHidden echo suppression', () => {
  it('prints the question and a newline, and never the typed value', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type(`${TYPED}\r`);
    await expect(pending).resolves.toBe(TYPED);

    // Positive control first: a suite that asserted only absence would pass on
    // an output that was never written at all.
    expect(h.out.written).toBe('Value: \n');
    expectNoEchoOf(h.out.written, TYPED);
    expect(h.err.written).toBe('');
  });

  it('prints nothing of a value that was cancelled part-way', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type(TYPED.slice(0, 9));
    h.tty.type('\u0003');
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(h.out.written).toBe('Value: \n');
    expectNoEchoOf(h.out.written, TYPED.slice(0, 9));
  });

  it('keeps arrow keys and backspace out of the captured value', async () => {
    // The user cannot see what they typed, so a swallowed escape sequence or a
    // mishandled backspace corrupts the secret silently — it is only found out
    // later, when the value does not work.
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type('abc');
    h.tty.type('\u001b[D'); // left arrow
    h.tty.type('\u007f'); // backspace
    h.tty.type('XY\r');
    await expect(pending).resolves.toBe('abXY');
  });

  it('reads a value split across chunks, as a terminal delivers it', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    for (const ch of TYPED) h.tty.type(ch);
    h.tty.type('\r');
    await expect(pending).resolves.toBe(TYPED);
  });
});

// -------------------------------------------------------------------------
// The fatal-signal path
// -------------------------------------------------------------------------

describe('askHidden signal handling', () => {
  it('registers a handler for each cleanup signal and removes them all', async () => {
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    expect(h.registered()).toEqual(['SIGINT', 'SIGTERM', 'SIGHUP']);

    h.tty.type('\r');
    await pending;
    expect(h.registered()).toEqual([]);
  });

  it('restores the terminal BEFORE re-raising the signal', () => {
    // The order is the whole point. Re-raise first and the default disposition
    // kills the process with raw mode still on, leaving the user's shell with
    // no echo and no prompt — recoverable only by `stty sane` or a new window.
    const h = harness();
    const pending = terminalPrompter(h.io).askHidden('Value: ');
    h.tty.type(TYPED.slice(0, 6));
    h.deliver('SIGTERM');

    // Asserted as the state the raise INTERRUPTED, not the state afterwards:
    // after the handler returns both statements have run whichever order they
    // are in, so a plain `rawModeNow` check here cannot tell the two apart.
    expect(h.raised()).toEqual([
      { signal: 'SIGTERM', rawModeAtRaise: false, dataListenersAtRaise: 0 },
    ]);

    // `pending` is deliberately left unsettled, and cannot be settled from
    // here: restore() removed the data listener, so no further keystroke
    // reaches the reducer. That is the production shape — the signal's default
    // disposition ends the process, and askHidden hands the outcome to it
    // rather than resolving behind its back. Referenced so the promise is not
    // read as forgotten.
    expect(pending).toBeInstanceOf(Promise);
    expect(h.tty.listenerCount('data')).toBe(0);
  });

  it('re-raises the signal it was given, not a fixed one', () => {
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
      const h = harness();
      const pending = terminalPrompter(h.io).askHidden('Value: ');
      h.deliver(signal);
      expect(h.raised().map((record) => record.signal)).toEqual([signal]);
      // Unsettled by design, as above.
      expect(pending).toBeInstanceOf(Promise);
    }
  });
});

// -------------------------------------------------------------------------
// isInteractive
// -------------------------------------------------------------------------

describe('isInteractive', () => {
  it('is true only when both streams are TTYs', () => {
    const both = harness();
    expect(terminalPrompter(both.io).isInteractive).toBe(true);

    const noInput = harness();
    noInput.tty.isTTY = false;
    expect(terminalPrompter(noInput.io).isInteractive).toBe(false);

    const noOutput = harness();
    noOutput.out.isTTY = false;
    expect(terminalPrompter(noOutput.io).isInteractive).toBe(false);
  });
});

// -------------------------------------------------------------------------
// What only Windows can answer
// -------------------------------------------------------------------------

// Everything above runs the raw-mode protocol against a stand-in. These two run
// against Node's real signal and tty layers on the platform whose behaviour
// differs, and they are the reason this file is worth having on a Windows
// runner rather than only on Linux.
describe('Windows terminal behaviour', () => {
  it.runIf(process.platform === 'win32')('accepts every cleanup signal', () => {
    // Windows has no unix signals; Node emulates a subset and throws
    // ERR_UNKNOWN_SIGNAL for the rest. askHidden registers all three
    // unconditionally, before it reads a single keystroke — so a name Node
    // rejects there is not a degraded prompt but a thrown prompt, on the one
    // platform nothing in CI exercises.
    const noop = (): void => {
      // Registration is the property; the handler is never invoked.
    };
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
      expect(() => {
        process.once(signal, noop);
        process.removeListener(signal, noop);
      }).not.toThrow();
    }
  });

  it.runIf(process.platform === 'win32')('exposes setRawMode on a Windows TTY', () => {
    // `setRawMode` is a member of tty.ReadStream, not of a pipe. CI redirects
    // stdin, so what can be asserted here is the shape of the class Node
    // installs on Windows — a build without conio raw-mode support would leave
    // askHidden throwing TypeError at the first prompt.
    expect(typeof ReadStream.prototype.setRawMode).toBe('function');
  });
});
