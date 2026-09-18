// The two stdio helpers in `shared.ts` that are neither the wire union nor the
// fail-open wrapper: `readStdin`, which every hook calls first, and
// `baseMetadata`, which stamps what a capture is attributed to.
//
// Both were reachable only through a spawned process before this file, so
// nothing in-process saw them — and the e2e that drives them cannot distinguish
// "settled on end" from "settled on the timeout", or see that a listener was
// removed at all. Those are the properties here.
//
// `emit`, `runHookFailOpen` and the `HookOutput` union are covered in
// ./fail-open-wrapper.test.ts and ../hook-output-shapes.test.ts; this file
// deliberately does not restate them.
import { EventEmitter } from 'node:events';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { baseMetadata, getString, parseJson, readStdin } from '../../src/hooks/shared.ts';

/**
 * A stand-in for `process.stdin` carrying only what `readStdin` touches.
 *
 * An EventEmitter rather than a mock object, so `on`/`removeListener` really
 * behave — the listener-removal case below is asserting emitter state, and a
 * hand-rolled stub would let it pass by construction.
 */
class FakeStdin extends EventEmitter {
  public encoding: string | undefined;

  public setEncoding(encoding: string): this {
    this.encoding = encoding;
    return this;
  }
}

/**
 * Install `fake` as `process.stdin` for the WHOLE of `body`, including whatever
 * it awaits.
 *
 * Restoring synchronously after kicking off `readStdin()` looks equivalent and
 * is not: `finish()` calls `process.stdin.removeListener(...)` when the stream
 * settles, which is a later turn — so the removal would land on the real stdin
 * and the fake would keep its listeners. That is a harness bug that reads
 * exactly like a product leak, and it cost this file a false red once.
 */
async function withStdin<T>(fake: FakeStdin, body: () => Promise<T>): Promise<T> {
  const original = Object.getOwnPropertyDescriptor(process, 'stdin');
  Object.defineProperty(process, 'stdin', { value: fake, configurable: true });
  try {
    return await body();
  } finally {
    if (original) Object.defineProperty(process, 'stdin', original);
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('readStdin', () => {
  it('concatenates every chunk and resolves on end', async () => {
    const fake = new FakeStdin();
    // Chunked deliberately: a payload past the pipe buffer arrives in several
    // reads, and an implementation keeping only the last chunk would pass a
    // single-chunk case.
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', '{"tool');
      fake.emit('data', 'Name":"bash"}');
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('{"toolName":"bash"}');
  });

  it('asks for utf8 rather than decoding Buffers by hand', async () => {
    const fake = new FakeStdin();
    await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('end');
      return pending;
    });
    expect(fake.encoding).toBe('utf8');
  });

  it('resolves empty when stdin ends with nothing', async () => {
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('');
  });

  it('resolves rather than rejecting on an error event', async () => {
    // An unhandled 'error' on stdin is an uncaughtException, not a rejection —
    // it would kill the hook with a non-zero exit, which on the Copilot CLI is a
    // DENY. Settling instead is what keeps the exit at 0.
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'partial');
      fake.emit('error', new Error('EPIPE'));
      return pending;
    });
    expect(got).toBe('partial');
  });

  it('settles with whatever arrived when stdin never closes', async () => {
    // The 5s guard. A host that opens the pipe and never ends it would otherwise
    // hang the hook past its own timeout — and a timed-out hook is allowed
    // through unscanned.
    vi.useFakeTimers();
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'arrived before the stall');
      await vi.advanceTimersByTimeAsync(5_000);
      return pending;
    });
    expect(got).toBe('arrived before the stall');
  });

  it('settles ONCE — a late end after the timeout changes nothing', async () => {
    // The `settled` latch. Without it the second settle path would call
    // `resolve` again (harmless) but also re-enter the listener removal, and a
    // future edit that resolved with a fresh buffer would silently truncate.
    vi.useFakeTimers();
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'first');
      await vi.advanceTimersByTimeAsync(5_000);
      fake.emit('data', 'second');
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('first');
  });

  it('removes its data and end listeners once settled', async () => {
    // Asserted on the emitter rather than inferred: a hook process is short
    // lived, so a leak here is invisible at runtime and only shows up as a
    // surprise when the handle is reused.
    const fake = new FakeStdin();
    await withStdin(fake, async () => {
      const pending = readStdin();
      // Both halves: a version that never attached would satisfy the removal
      // check trivially.
      expect(fake.listenerCount('data')).toBe(1);
      expect(fake.listenerCount('end')).toBe(1);
      fake.emit('end');
      return pending;
    });
    expect(fake.listenerCount('data')).toBe(0);
    expect(fake.listenerCount('end')).toBe(0);
  });
});

describe('baseMetadata', () => {
  it('reads the session id in the CLI casing', () => {
    expect(baseMetadata('cli', { sessionId: 'abc', cwd: '/nonexistent-xyz' })?.sessionId).toBe(
      'abc',
    );
  });

  it('reads the session id in the VS Code casing', () => {
    expect(baseMetadata('vscode', { session_id: 'abc' })?.sessionId).toBe('abc');
  });

  it('does not read the other dialect’s spelling', () => {
    // The tables are per dialect all the way down; picking up `session_id` on
    // the CLI would attribute a capture to a session that host never sent.
    //
    // Asserted on `sessionId` rather than on the whole record: the CLI branch
    // still falls back to `process.cwd()` for the repo, so its result is
    // non-empty here for a reason that has nothing to do with the session id.
    expect(baseMetadata('cli', { session_id: 'abc' })?.sessionId).toBeUndefined();
    expect(baseMetadata('vscode', { sessionId: 'abc' })).toBeUndefined();
  });

  it('falls back to the process cwd on the CLI when the payload carries none', () => {
    // On the CLI the hook's own cwd is the workspace, so the fallback is
    // correct there. Driven from the repo root, where `resolveRepo` resolves,
    // so this asserts the fallback FIRED rather than that it returned nothing.
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(process.cwd());
    const meta = baseMetadata('cli', { sessionId: 's' });
    expect(spy).toHaveBeenCalled();
    expect(meta?.repo).toBeTypeOf('string');
  });

  it('does NOT fall back to the process cwd under VS Code', () => {
    // The load-bearing asymmetry. That host's spawn defaults its cwd to the HOME
    // DIRECTORY, so falling back would resolve a repo from `~` and stamp every
    // capture with whatever happens to live there.
    const spy = vi.spyOn(process, 'cwd');
    const meta = baseMetadata('vscode', { session_id: 's' });
    expect(spy).not.toHaveBeenCalled();
    expect(meta?.repo).toBeUndefined();
  });

  it('returns undefined when nothing at all could be derived', () => {
    // So callers can keep passing the optional metadata straight through.
    expect(baseMetadata('vscode', {})).toBeUndefined();
  });

  it('omits the repo when the cwd resolves to none', () => {
    const meta = baseMetadata('vscode', { session_id: 's', cwd: '/definitely/not/a/repo/xyz' });
    expect(meta).toEqual({ sessionId: 's' });
  });
});

describe('parseJson / getString', () => {
  it('accepts an object and rejects the shapes a payload must not be', () => {
    // `readToolCall` indexes the result, so an array or a scalar reaching it
    // would read fields off the wrong kind of value rather than declining.
    expect(parseJson('{"a":1}')).toEqual({ a: 1 });
    expect(parseJson('[1,2]')).toBeNull();
    expect(parseJson('"str"')).toBeNull();
    expect(parseJson('null')).toBeNull();
    expect(parseJson('not json')).toBeNull();
  });

  it('returns a string field only when it really is a string', () => {
    expect(getString({ a: 'x' }, 'a')).toBe('x');
    expect(getString({ a: 7 }, 'a')).toBeUndefined();
    expect(getString({}, 'a')).toBeUndefined();
  });
});
