import { EventEmitter } from 'node:events';
import { existsSync, mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import {
  ATTRIBUTION_HOLD_MAX_AGE_MS,
  ATTRIBUTION_HOLD_MAX_PASSES,
} from '@akasecurity/plugin-sdk/account';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type FakeChild = EventEmitter & { unref: () => void };

// A child process is an EventEmitter: a spawn that cannot start reports through it.
function fakeChild(unref: () => void = vi.fn()): FakeChild {
  return Object.assign(new EventEmitter(), { unref });
}

// Mock the detached spawn so the test never launches a real worker — we only assert
// HOW OFTEN it would fire. `vi.hoisted` makes the spy exist before the mock factory.
const { spawnSpy } = vi.hoisted(() => ({
  spawnSpy: vi.fn<(command: string, args: readonly string[], options: object) => FakeChild>(() =>
    fakeChild(),
  ),
}));
vi.mock('node:child_process', () => ({ spawn: spawnSpy }));

// `throttled` (@akasecurity/plugin-sdk) is left REAL: it writes the on-disk
// marker we're testing, against a temp dataDir.
import {
  FOLLOW_UP_DELAYS_MS,
  planFollowUp,
  scheduleFollowUp,
  triggerReconcile,
} from '../../src/history/reconcile-trigger.ts';

describe('triggerReconcile — per-session throttle', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-reconcile-'));
    spawnSpy.mockReset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('throttles per session, not globally — concurrent sessions each get their own spawn', () => {
    // First turn of session A → spawns (no marker yet).
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    // A second turn of session A within the 30s window is batched (throttled).
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(1);

    // A DIFFERENT concurrent session (another tab/project) must NOT be starved by
    // session A's marker — with a global marker it would be throttled and its live
    // capture delayed; with the per-session marker it spawns immediately.
    triggerReconcile(dir, 'sess-B', '/t/b.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(2);
  });

  it('removes markers of sessions idle past a day, and keeps every recent one', () => {
    const day = 24 * 60 * 60 * 1000;
    const old = join(dir, 'reconcile-last-attempt-sess-old');
    const recent = join(dir, 'reconcile-last-attempt-sess-recent');
    const unrelated = join(dir, 'session-start-last');
    for (const file of [old, recent, unrelated]) writeFileSync(file, '0');
    const longAgo = new Date(Date.now() - 2 * day);
    utimesSync(old, longAgo, longAgo);
    utimesSync(unrelated, longAgo, longAgo);
    const lastHour = new Date(Date.now() - 60 * 60 * 1000);
    utimesSync(recent, lastHour, lastHour);

    triggerReconcile(dir, 'sess-new', '/t/new.jsonl');

    expect(spawnSpy).toHaveBeenCalledTimes(1);
    expect(existsSync(old)).toBe(false);
    // The positive control: the sweep ran, and still left alone what it must.
    expect(existsSync(recent)).toBe(true);
    expect(existsSync(unrelated)).toBe(true);
    expect(existsSync(join(dir, 'reconcile-last-attempt-sess-new'))).toBe(true);
  });
});

describe('scheduleFollowUp — a detached worker that waits for its due time', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-follow-up-'));
    spawnSpy.mockReset();
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("spawns the reconcile worker detached, unref'd and with no stdio, naming the session, the transcript and the due time", () => {
    const unref = vi.fn();
    spawnSpy.mockReturnValueOnce(fakeChild(unref));
    scheduleFollowUp('sess-A', '/t/a.jsonl', 1_700_000_000_000);
    expect(spawnSpy).toHaveBeenCalledTimes(1);
    const [command, args, options] = spawnSpy.mock.calls[0] ?? [];
    expect(command).toBe(process.execPath);
    expect(basename(args?.[0] ?? '')).toBe('reconcile.js');
    expect(args?.slice(1)).toEqual(['sess-A', '/t/a.jsonl', '1700000000000']);
    expect(options).toEqual({ detached: true, stdio: 'ignore' });
    expect(unref).toHaveBeenCalledTimes(1);
  });

  it('spawns the same worker triggerReconcile does', () => {
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    scheduleFollowUp('sess-B', '/t/b.jsonl', 5);
    const [first, second] = spawnSpy.mock.calls;
    expect(second?.[0]).toBe(first?.[0]);
    expect(second?.[1]?.[0]).toBe(first?.[1]?.[0]);
  });

  it('is not held back by the reconcile throttle, and leaves no throttle marker', () => {
    triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
    expect(readdirSync(dir)).toEqual(['reconcile-last-attempt-sess-A']);
    scheduleFollowUp('sess-A', '/t/a.jsonl', 5);
    expect(spawnSpy).toHaveBeenCalledTimes(2);
    scheduleFollowUp('sess-F', '/t/f.jsonl', 5);
    expect(spawnSpy).toHaveBeenCalledTimes(3);
    expect(readdirSync(dir)).toEqual(['reconcile-last-attempt-sess-A']);
    triggerReconcile(dir, 'sess-F', '/t/f.jsonl');
    expect(spawnSpy).toHaveBeenCalledTimes(4);
  });

  it('swallows a spawn that fails', () => {
    spawnSpy.mockImplementationOnce(() => {
      throw new Error('the worker cannot be started');
    });
    expect(() => {
      scheduleFollowUp('sess-A', '/t/a.jsonl', 5);
    }).not.toThrow();
    expect(spawnSpy).toHaveBeenCalledTimes(1);
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
    [
      'triggerReconcile',
      () => {
        triggerReconcile(dir, 'sess-A', '/t/a.jsonl');
      },
    ],
    [
      'scheduleFollowUp',
      () => {
        scheduleFollowUp('sess-A', '/t/a.jsonl', 5);
      },
    ],
  ])('%s leaves the error event of a failed spawn handled', async (_caller, ask) => {
    const unref = vi.fn();
    const child = fakeChild(unref);
    spawnSpy.mockReturnValueOnce(child);
    expect(ask).not.toThrow();
    expect(spawnSpy).toHaveBeenCalledTimes(1);
    expect(unref).toHaveBeenCalledTimes(1);
    await expect(failToStart(child)).resolves.toBeUndefined();
  });
});

describe('FOLLOW_UP_DELAYS_MS', () => {
  it('names a wait for each pass the hold budget allows to hold', () => {
    expect(FOLLOW_UP_DELAYS_MS).toHaveLength(ATTRIBUTION_HOLD_MAX_PASSES);
  });

  it('adds up to less than the time the hold budget allows, so the pass after the last wait writes inside it', () => {
    const total = FOLLOW_UP_DELAYS_MS.reduce((sum, delay) => sum + delay, 0);
    expect(total).toBeLessThan(ATTRIBUTION_HOLD_MAX_AGE_MS);
  });

  it('starts at thirty seconds, two minutes and six minutes', () => {
    expect([...FOLLOW_UP_DELAYS_MS]).toEqual([30_000, 120_000, 360_000]);
  });
});

describe('planFollowUp — when a held pass asks for a follow-up', () => {
  const held = (passes: number) => ({ passes, since: 100 });

  it.each([
    [1, 30_000],
    [2, 120_000],
    [3, 360_000],
  ])('asks for one after the %s-th held pass, %s ms on', (passes, delay) => {
    expect(
      planFollowUp({ held: held(passes), before: undefined, ownDue: undefined, now: 1_000 }),
    ).toEqual({
      pending: { passes, since: 100, followUpAt: 1_000 + delay },
      dueAt: 1_000 + delay,
    });
  });

  it('asks for none while the follow-up already asked for is not due, and keeps its due time', () => {
    expect(
      planFollowUp({
        held: held(2),
        before: { passes: 1, since: 100, followUpAt: 5_000 },
        ownDue: undefined,
        now: 1_000,
      }),
    ).toEqual({ pending: { passes: 2, since: 100, followUpAt: 5_000 }, dueAt: undefined });
  });

  it.each([
    ['due', 1_000],
    ['past due', 900],
  ])('asks again when the follow-up already asked for is %s', (_label, followUpAt) => {
    expect(
      planFollowUp({
        held: held(2),
        before: { passes: 1, since: 100, followUpAt },
        ownDue: undefined,
        now: 1_000,
      }),
    ).toEqual({ pending: { passes: 2, since: 100, followUpAt: 121_000 }, dueAt: 121_000 });
  });

  it('asks again from the follow-up that is the one asked for, even a little before its due time', () => {
    expect(
      planFollowUp({
        held: held(2),
        before: { passes: 1, since: 100, followUpAt: 1_001 },
        ownDue: 1_001,
        now: 1_000,
      }),
    ).toEqual({ pending: { passes: 2, since: 100, followUpAt: 121_000 }, dueAt: 121_000 });
  });

  it('asks for none past the last pass the hold budget allows to hold', () => {
    expect(
      planFollowUp({ held: held(4), before: undefined, ownDue: undefined, now: 1_000 }),
    ).toEqual({ pending: { passes: 4, since: 100 }, dueAt: undefined });
  });
});
