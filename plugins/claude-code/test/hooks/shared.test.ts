import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { countFailOpen, emit, readStdin } from '../../src/hooks/shared.ts';

// A hook calls countFailOpen() with no base, so the home directory is resolved
// on its own path — and `os.homedir()` throws when the platform cannot name
// one. The toggle makes that refusal reachable; every other call in this file
// gets the real function.
const osHome = vi.hoisted(() => ({ refuse: false }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.refuse) throw new Error('no home directory');
      return actual.homedir();
    },
  };
});

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

    await expect(emit({ systemMessage: 'ok' })).resolves.toBeUndefined();
    expect(writeSpy).toHaveBeenCalledWith(
      JSON.stringify({ systemMessage: 'ok' }),
      expect.any(Function),
    );

    writeSpy.mockRestore();
  });

  it('resolves instead of throwing when stdout emits an error before the write callback fires', async () => {
    const writeSpy = vi
      .spyOn(process.stdout, 'write')
      // A broken pipe (EPIPE) surfaces as an 'error' event, not a write callback.
      .mockImplementation(() => true);

    const promise = emit({ systemMessage: 'ok' });
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

    await emit({ systemMessage: 'ok' });

    // Deliberately NOT removed (see shared.ts) — one more listener than
    // before, guarding against any stdout error between resolving and exit.
    expect(process.stdout.listenerCount('error')).toBe(before + 1);
    writeSpy.mockRestore();
  });
});

describe('countFailOpen', () => {
  // Called from inside every hook entry's top-level catch. Two things have to
  // hold there and nowhere else matters as much: it must never throw (a throw
  // inside that catch escapes as an uncaught exception and turns a silent
  // allow into a non-zero exit), and it must never print (the host reads an
  // empty stdout as "no opinion", and one byte would change that).
  let base: string;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-count-fail-open-'));
  });

  afterEach(() => {
    rmSync(base, { recursive: true, force: true });
  });

  it('counts one exit per call under the home it is given, and prints nothing', () => {
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      countFailOpen(base);
      countFailOpen(base);
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      writeSpy.mockRestore();
    }
    expect(readHookFailOpens(join(base, 'data'))).toMatchObject({ failOpens: 2 });
  });

  it('never throws, even where nothing under the home can be written', () => {
    const blocker = join(base, 'not-a-dir');
    writeFileSync(blocker, '');
    expect(() => {
      countFailOpen(join(blocker, 'home'));
    }).not.toThrow();
  });

  it('never throws when the home directory itself cannot be resolved', () => {
    // The production call passes no base, so `dataDir()` asks `os.homedir()`,
    // and that question is asked BEFORE `recordHookFailOpen`'s own guard runs.
    osHome.refuse = true;
    const writeSpy = vi.spyOn(process.stdout, 'write');
    try {
      expect(() => {
        countFailOpen();
      }).not.toThrow();
      expect(writeSpy).not.toHaveBeenCalled();
    } finally {
      osHome.refuse = false;
      writeSpy.mockRestore();
    }
  });
});
