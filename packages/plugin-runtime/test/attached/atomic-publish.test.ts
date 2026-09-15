/**
 * The retry exists for a platform this suite does not run on, which is exactly
 * why it needs a test that does.
 *
 * `publishByRename` was added because the Windows leg — once its install step
 * was fixed and the attached suites could run there for the first time — failed
 * the policy cache's concurrent-publish cases with EPERM. POSIX `rename(2)`
 * replaces a destination no matter who holds it open, so nothing on macOS or
 * Linux can provoke the refusal this handles, and driven against a real rename
 * the retry branch would be dead code everywhere it is tested.
 *
 * So the failure is injected through the `move` seam: a fake that refuses a
 * bounded number of times then succeeds, and one that refuses forever. Between
 * them they pin that the retry retries, that it gives up rather than stalling a
 * hook, and that a code it was never meant to swallow is rethrown at once.
 */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { publishByRename } from '../../src/attached/atomic-publish.ts';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aka-atomic-publish-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const errno = (code: string): NodeJS.ErrnoException => Object.assign(new Error(code), { code });

/**
 * Resolves after `n` turns of the event loop, or sooner once `stop` reports
 * true: a wait no faked timer can shorten or stall, and one that stops turning
 * once the case it raced against has settled.
 */
const loopTurns = async (n: number, stop: () => boolean = () => false): Promise<void> => {
  for (let i = 0; i < n && !stop(); i += 1) {
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
};

describe('publishByRename', () => {
  it('lands the file through a real rename', async () => {
    // The positive control, and the one case that uses the default `move`.
    // Without it every assertion below could be satisfied by a function that
    // throws on the happy path too.
    const tmp = join(dir, 'cache.tmp');
    const file = join(dir, 'cache.json');
    await writeFile(tmp, '{"v":1}', 'utf8');

    await publishByRename(tmp, file);

    await expect(readFile(file, 'utf8')).resolves.toBe('{"v":1}');
  });

  it('survives a destination that is briefly locked, as Windows does', async () => {
    // Two refusals then success — the shape of a concurrent reader releasing a
    // handle. A single-attempt implementation fails this.
    let attempts = 0;
    const flaky = (): Promise<void> => {
      attempts += 1;
      if (attempts <= 2) return Promise.reject(errno('EPERM'));
      return Promise.resolve();
    };

    await expect(publishByRename('tmp', 'file', flaky)).resolves.toBeUndefined();
    expect(attempts).toBe(3);
  });

  it('retries a refusal from a racing rename without waiting on a timer', async () => {
    // A rename refused because another rename to the same destination is in
    // flight clears as soon as that rename lands, which on the Windows leg is
    // well under a millisecond — while a timer there waits a whole ~14ms tick.
    // Sleeping woke every refused writer on the same tick to collide again.
    // Timers are faked and never advanced, so a retry that sleeps never gets
    // its second attempt and the race below reports it still waiting.
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      let attempts = 0;
      const racing = (): Promise<void> => {
        attempts += 1;
        return attempts <= 8 ? Promise.reject(errno('EPERM')) : Promise.resolve();
      };

      // Both branches end cleanly whichever wins: the publish branch handles its
      // own rejection, and the waiter stops turning once the publish settles.
      let settled = false;
      const outcome = await Promise.race([
        publishByRename('tmp', 'file', racing)
          .then(
            () => 'landed',
            () => 'threw',
          )
          .finally(() => {
            settled = true;
          }),
        loopTurns(200, () => settled).then(() => 'still waiting'),
      ]);

      expect(outcome).toBe('landed');
      expect(attempts).toBe(9);
    } finally {
      vi.useRealTimers();
    }
  });

  it('waits out a held destination on the timed tail: 10, 20, 30 then 40ms', async () => {
    // The other half of the schedule. A handle another process holds open does
    // not clear when a racing rename lands, so once the eight immediate retries
    // are spent each further attempt waits on a timer. Timers are faked and
    // moved by hand, a millisecond short of each delay and then onto it: a tail
    // that never touches a timer, a split in a different place, or a different
    // delay each fails the count at the step where it differs.
    vi.useFakeTimers({ toFake: ['setTimeout'] });
    try {
      let attempts = 0;
      const held = (): Promise<void> => {
        attempts += 1;
        return Promise.reject(errno('EBUSY'));
      };
      let outcome: unknown = 'pending';
      const publishing = publishByRename('tmp', 'file', held).then(
        () => {
          outcome = 'landed';
        },
        (err: unknown) => {
          outcome = err;
        },
      );

      // The first attempt and eight immediate retries, then a wait on a timer.
      await loopTurns(50);
      expect(attempts).toBe(9);

      for (const [ms, attemptsOnceElapsed] of [
        [10, 10],
        [20, 11],
        [30, 12],
        [40, 13],
      ] as const) {
        await vi.advanceTimersByTimeAsync(ms - 1);
        await loopTurns(5);
        expect(attempts, `before the ${String(ms)}ms wait elapsed`).toBe(attemptsOnceElapsed - 1);
        await vi.advanceTimersByTimeAsync(1);
        await loopTurns(5);
        expect(attempts, `once the ${String(ms)}ms wait elapsed`).toBe(attemptsOnceElapsed);
      }

      await publishing;
      expect((outcome as NodeJS.ErrnoException).code).toBe('EBUSY');
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('gives up rather than stalling a hook when the lock never clears', async () => {
    // A destination held open indefinitely is not a race, and the caller is
    // better served by an error it can record than by a hook that waits: eight
    // immediate retries, then four timed ones, then the error.
    let attempts = 0;
    const always = (): Promise<void> => {
      attempts += 1;
      return Promise.reject(errno('EBUSY'));
    };

    await expect(publishByRename('tmp', 'file', always)).rejects.toThrow('EBUSY');
    expect(attempts).toBe(13);
  });

  it('rethrows a code the retry was never meant to swallow, immediately', async () => {
    // ENOENT means the temp file is gone — retrying cannot help, and hiding it
    // behind five attempts would delay a real error for no reason.
    let attempts = 0;
    const missing = (): Promise<void> => {
      attempts += 1;
      return Promise.reject(errno('ENOENT'));
    };

    await expect(publishByRename('tmp', 'file', missing)).rejects.toThrow('ENOENT');
    expect(attempts).toBe(1);
  });
});
