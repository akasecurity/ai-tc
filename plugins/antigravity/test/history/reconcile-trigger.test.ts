// The reconcile trigger's tests, as in the Claude Code plugin's, without the
// follow-up cases that exist only there — no harness-specific logic here.
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type FakeChild = EventEmitter & { unref: () => void };

// A child process is an EventEmitter: a spawn that cannot start reports through it.
function fakeChild(unref: () => void = vi.fn()): FakeChild {
  return Object.assign(new EventEmitter(), { unref });
}

// Mock the detached spawn so the test never launches a real worker — we only assert
// HOW OFTEN it would fire and with what. `vi.hoisted` makes the spy exist before
// the mock factory.
const { spawnSpy } = vi.hoisted(() => ({
  spawnSpy: vi.fn<(command: string, args: readonly string[], options: object) => FakeChild>(),
}));
vi.mock('node:child_process', () => ({ spawn: spawnSpy }));

// `gatePerKey` (@akasecurity/plugin-sdk) is left REAL: it writes the on-disk
// marker we're testing, against a temp dataDir.
import { triggerReconcile } from '../../src/history/reconcile-trigger.ts';

const WINDOW_MS = 30_000;

describe('triggerReconcile — per-session throttle', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-reconcile-'));
    spawnSpy.mockReset();
    spawnSpy.mockImplementation(() => fakeChild());
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('throttles per session, not globally — concurrent sessions each get their own spawn', () => {
    // First turn of session A → spawns (no marker yet).
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(1);
    // A second turn of session A within the 30s window is batched: it spawns no
    // pass of its own, only the one trailing worker that waits for the window to
    // close, and a third turn adds nothing to it.
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(2);

    // A DIFFERENT concurrent session must NOT be starved by session A's marker.
    triggerReconcile(dir, 'sess-B', '/t/b.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(3);
    expect(spawnSpy.mock.calls[2]?.[1]).toHaveLength(3);
  });
});

describe('triggerReconcile — the last call of a throttle window', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-reconcile-trail-'));
    spawnSpy.mockReset();
    spawnSpy.mockImplementation(() => fakeChild());
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('spawns a worker for a call the throttle holds back, due when the window closes', () => {
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    const windowStart = statSync(join(dir, 'reconcile-last-attempt-sess-A')).mtimeMs;

    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');

    expect(spawnSpy).toHaveBeenCalledTimes(2);
    const [command, args, options] = spawnSpy.mock.calls[1] ?? [];
    expect(command).toBe(process.execPath);
    expect(basename(args?.[0] ?? '')).toBe('reconcile.js');
    const [sessionId, transcript, due, ...rest] = args?.slice(1) ?? [];
    expect([sessionId, transcript, rest]).toEqual(['sess-A', '/t/a.jsonl', []]);
    expect(Number(due)).toBeGreaterThanOrEqual(windowStart + WINDOW_MS);
    expect(Number(due)).toBeLessThanOrEqual(windowStart + WINDOW_MS + 1);
    expect(options).toEqual({ detached: true, stdio: 'ignore' });
  });

  it('spawns one trailing worker per window, however many calls the window holds back', () => {
    for (let call = 0; call < 6; call += 1) triggerReconcile(dir, 'sess-A', '/t/a.jsonl');

    expect(spawnSpy).toHaveBeenCalledTimes(2);
    expect(spawnSpy.mock.calls[0]?.[1]).toHaveLength(3);
    expect(spawnSpy.mock.calls[1]?.[1]).toHaveLength(4);
  });

  it('spawns the next trailing worker from the due time of the last, for a call that lands after it', () => {
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    // The marker now holds the due time of the trailing worker just spawned. Put
    // that time ten seconds in the past.
    const pastDue = new Date(Date.now() - 10_000);
    utimesSync(join(dir, 'reconcile-last-attempt-sess-A'), pastDue, pastDue);

    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');

    expect(spawnSpy).toHaveBeenCalledTimes(3);
    const due = Number(spawnSpy.mock.calls[2]?.[1]?.[3]);
    expect(due).toBeGreaterThanOrEqual(pastDue.getTime() + WINDOW_MS);
    expect(due).toBeLessThanOrEqual(pastDue.getTime() + WINDOW_MS + 1);
  });

  it('swallows a failure to spawn the trailing worker, and schedules another once its window has closed', () => {
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    spawnSpy.mockImplementationOnce(() => {
      throw new Error('the worker cannot be started');
    });
    expect(() => {
      triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    }).not.toThrow();
    expect(spawnSpy).toHaveBeenCalledTimes(2);

    // The rest of that window is answered as if the worker were waiting.
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(2);

    // Past the due time the marker records, the next call schedules again.
    const pastDue = new Date(Date.now() - 10_000);
    utimesSync(join(dir, 'reconcile-last-attempt-sess-A'), pastDue, pastDue);
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(3);
    expect(spawnSpy.mock.calls[2]?.[1]).toHaveLength(4);
  });
});

describe('a worker that cannot be started', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-spawn-error-'));
    spawnSpy.mockReset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // Node reports a spawn failure (ENOENT, EACCES, EAGAIN, EMFILE) as an 'error' event on the
  // child after spawn has returned, and an emitter with no listener throws from emit.
  function failToStart(child: EventEmitter): Promise<unknown> {
    return new Promise((resolve) => {
      process.nextTick(() => {
        try {
          child.emit('error', Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' }));
          resolve(undefined);
        } catch (thrown) {
          resolve(thrown);
        }
      });
    });
  }

  it.each([
    ['the pass of a window', 0],
    ['the trailing pass of a window', 1],
  ])('leaves the error event of a failed spawn handled for %s', async (_label, held) => {
    const children = [fakeChild(), fakeChild()];
    for (const child of children) spawnSpy.mockReturnValueOnce(child);
    for (let call = 0; call <= held; call += 1) triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(held + 1);

    await expect(failToStart(children[held] ?? fakeChild())).resolves.toBeUndefined();
  });
});
