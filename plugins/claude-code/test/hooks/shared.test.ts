import { afterEach, describe, expect, it, vi } from 'vitest';

import { emit, readStdin } from '../../src/hooks/shared.ts';

describe('readStdin', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('resolves with the accumulated chunks once stdin ends normally', async () => {
    const promise = readStdin();
    process.stdin.emit('data', 'hello ');
    process.stdin.emit('data', 'world');
    process.stdin.emit('end');
    await expect(promise).resolves.toBe('hello world');
  });

  it('resolves with whatever was read so far instead of throwing on a stdin error', async () => {
    const promise = readStdin();
    process.stdin.emit('data', 'partial');
    process.stdin.emit('error', new Error('simulated stdin failure'));
    await expect(promise).resolves.toBe('partial');
  });

  it('resolves with whatever was read so far after a 5s stall, instead of hanging forever', async () => {
    vi.useFakeTimers();
    const promise = readStdin();
    process.stdin.emit('data', 'stalled');
    vi.advanceTimersByTime(5_000);
    await expect(promise).resolves.toBe('stalled');
  });

  it('removes its data/end listeners once settled, but keeps guarding against a later error', async () => {
    const before = {
      data: process.stdin.listenerCount('data'),
      end: process.stdin.listenerCount('end'),
      error: process.stdin.listenerCount('error'),
    };

    const promise = readStdin();
    process.stdin.emit('data', 'value');
    process.stdin.emit('end');
    await expect(promise).resolves.toBe('value');

    // data/end are genuinely done with — no reason to keep listening.
    expect(process.stdin.listenerCount('data')).toBe(before.data);
    expect(process.stdin.listenerCount('end')).toBe(before.end);
    // error is deliberately NOT removed (see shared.ts) — one more listener
    // than before, and a late error must not re-resolve or throw.
    expect(process.stdin.listenerCount('error')).toBe(before.error + 1);
    expect(() => process.stdin.emit('error', new Error('late, after settle'))).not.toThrow();
    await expect(promise).resolves.toBe('value');
  });

  it('clears its own pending timer once settled (no leaked timer past a normal end)', async () => {
    vi.useFakeTimers();
    const promise = readStdin();
    process.stdin.emit('end');
    await promise;
    // If the timeout were still pending, advancing past it would throw were
    // `finish` not idempotent — this just proves it's already been cleared.
    expect(() => vi.advanceTimersByTime(5_000)).not.toThrow();
  });
});

describe('emit', () => {
  it('resolves once the underlying write flushes', async () => {
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((
      _chunk: string,
      cb: () => void,
    ) => {
      cb();
      return true;
    }) as typeof process.stdout.write);

    await expect(emit({ ok: true })).resolves.toBeUndefined();
    expect(writeSpy).toHaveBeenCalledWith(JSON.stringify({ ok: true }), expect.any(Function));

    writeSpy.mockRestore();
  });

  it('resolves instead of throwing when stdout emits an error before the write callback fires', async () => {
    const writeSpy = vi
      .spyOn(process.stdout, 'write')
      // A broken pipe (EPIPE) surfaces as an 'error' event, not a write callback.
      .mockImplementation(() => true);

    const promise = emit({ ok: true });
    process.stdout.emit('error', new Error('EPIPE'));

    await expect(promise).resolves.toBeUndefined();
    writeSpy.mockRestore();
  });

  it('keeps its error listener attached after settling, so a later error still can not crash the process', async () => {
    const before = process.stdout.listenerCount('error');
    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(((
      _chunk: string,
      cb: () => void,
    ) => {
      cb();
      return true;
    }) as typeof process.stdout.write);

    await emit({ ok: true });

    // Deliberately NOT removed (see shared.ts) — one more listener than
    // before, guarding against any stdout error between resolving and exit.
    expect(process.stdout.listenerCount('error')).toBe(before + 1);
    writeSpy.mockRestore();
  });
});
