import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FileLockError, withFileLock } from '../src/file-lock.ts';

let dir: string;
let file: string;
let lock: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-file-lock-'));
  file = join(dir, 'settings.json');
  lock = `${file}.lock`;
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

// A held lock, without a second process. `pid` decides whether a waiter sees a
// LIVE holder or an abandoned one: this process is alive by definition, so it
// stands in for a real holder, while an unused pid stands in for one that died.
// `ageMs` backdates the lock's own recorded clock, which is what staleness is
// measured from — not the file's mtime.
function plantHeldLock({
  pid = process.pid,
  ageMs = 0,
  token = 'planted',
  host = hostname(),
} = {}): void {
  writeFileSync(lock, `${JSON.stringify({ pid, token, at: Date.now() - ageMs, host })}\n`);
}

// A pid no process on this machine holds, so `kill(pid, 0)` reports ESRCH.
// Above the platform maximum rather than merely unused, which a fresh fork could
// otherwise claim mid-test.
const DEAD_PID = 0x7ffffffe;

function backdate(path: string, ms: number): void {
  const when = new Date(Date.now() - ms);
  utimesSync(path, when, when);
}

// Long enough that nothing under test can age into staleness mid-run, so a case
// about exclusion is never quietly answered by the stale path instead.
const NEVER_STALE = { timeoutMs: 50, staleMs: 600_000 };

describe('withFileLock', () => {
  it('runs the body and returns its value', () => {
    expect(withFileLock(file, () => 'written')).toBe('written');
  });

  it('releases the lock once the body returns', () => {
    withFileLock(file, () => 'entered');
    expect(existsSync(lock)).toBe(false);
  });

  it('releases the lock when the body throws, and raises the body’s error', () => {
    const err = new Error('write failed');
    expect(() =>
      withFileLock(file, () => {
        throw err;
      }),
    ).toThrow(err);
    // A lock held by a failed write is the same wedge as one held by a killed
    // process, and this one is reachable without anybody dying.
    expect(existsSync(lock)).toBe(false);
  });

  it('excludes a second holder while the lock is held, even with no stale window', () => {
    let inner: unknown;
    withFileLock(file, () => {
      inner = (() => {
        try {
          // Not re-entrant, deliberately: the lock is held against every writer
          // on the machine, and this process is not a privileged one.
          //
          // `staleMs: 1` so the age test is satisfied instantly and the ONLY
          // thing that can refuse the steal is the holder-still-alive check.
          // Pinned with NEVER_STALE instead, this passes while a nested call
          // quietly steals its own live lock and leaves the outer section
          // running unguarded.
          return withFileLock(file, () => 'entered', { timeoutMs: 200, staleMs: 1 });
        } catch (err) {
          return err;
        }
      })();
    });
    expect(inner).toBeInstanceOf(FileLockError);
  });

  it('never runs the body when the lock cannot be taken', () => {
    plantHeldLock();
    let ran = false;
    expect(() => {
      withFileLock(
        file,
        () => {
          ran = true;
        },
        NEVER_STALE,
      );
    }).toThrow(FileLockError);
    // The whole point of failing loudly: the write does not happen anyway.
    expect(ran).toBe(false);
  });

  it('names the file and the holding pid on timeout', () => {
    plantHeldLock({ pid: 31337 });
    const err = errorFrom(() => withFileLock(file, () => 'entered', NEVER_STALE));
    expect(err).toBeInstanceOf(FileLockError);
    expect((err as FileLockError).reason).toBe('timeout');
    expect((err as FileLockError).file).toBe(file);
    expect((err as FileLockError).holderPid).toBe(31337);
    expect(err?.message).toContain('31337');
  });

  it('still reports a timeout when the lock body is unreadable', () => {
    // The pid decorates the message; it must never be what decides whether the
    // refusal happens.
    writeFileSync(lock, 'not json at all');
    const err = errorFrom(() => withFileLock(file, () => 'entered', NEVER_STALE));
    expect(err).toBeInstanceOf(FileLockError);
    expect((err as FileLockError).reason).toBe('timeout');
    expect((err as FileLockError).holderPid).toBeUndefined();
  });

  it('reports a directory that cannot hold a lock at all as unavailable', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX directory modes are what make the lock uncreatable here');
      return;
    }
    if (process.getuid?.() === 0) {
      ctx.skip('root bypasses directory mode bits, so the chmod below denies nothing');
      return;
    }
    // A read-only or unwritable directory is not contention, and waiting out the
    // full timeout to announce one as the other sends a reader looking for a
    // process that does not exist. It also blocks `aka init`, whose whole job is
    // repairing a store in exactly this state.
    //
    // The generous timeout is the assertion, not a cushion: this refusal has to
    // be IMMEDIATE. A retryable errno now falls back to probing the directory
    // when the lock path looks absent, so a probe that wrongly answered "this
    // directory takes creates" would turn this case into a 30s wait ending in
    // `timeout` — which `aka init` swallows, silently declining to write the
    // settings file it exists to create.
    const frozen = join(dir, 'frozen');
    mkdirSync(frozen);
    const target = join(frozen, 'settings.json');
    chmodSync(frozen, 0o500);
    try {
      const err = errorFrom(() =>
        withFileLock(target, () => 'entered', { timeoutMs: 30_000, staleMs: 30_000 }),
      );
      expect(err).toBeInstanceOf(FileLockError);
      expect((err as FileLockError).reason).toBe('unavailable');
      expect(err?.message).toContain(target);
    } finally {
      chmodSync(frozen, 0o700);
    }
  });

  // No case here drives the directory probe, and that is a statement rather
  // than an omission. The probe runs only where a retryable errno meets a lock
  // path that looks absent — Windows' delete-pending window — and POSIX has no
  // way to produce that combination: every route to EACCES/EPERM on the lock
  // also denies the probe and the `unavailable` case above already covers it,
  // while a dangling symlink answers EEXIST and never reaches the branch. A
  // case constructed here would create no probe at all and assert its absence
  // vacuously.
  //
  // What proves the fix is `test/concurrency/settings-race.test.ts` on the
  // Windows CI leg — the suite that caught the bug, where a concurrent handoff
  // was reported as a permanently unavailable directory.

  it('takes a lock whose holder is gone and whose window has passed', () => {
    plantHeldLock({ pid: DEAD_PID, ageMs: 5_000 });
    expect(withFileLock(file, () => 'entered', { timeoutMs: 1_000, staleMs: 1_000 })).toBe(
      'entered',
    );
    expect(existsSync(lock)).toBe(false);
  });

  it('never takes a lock whose holder is still alive, well past the stale window', () => {
    // Age alone must not evict anybody. A holder can outlive the window without
    // being dead — a suspended laptop, a throttled container, a slow network
    // home — and stealing from one puts two writers in the section, which is the
    // defect the lock exists to remove, reintroduced by its own recovery.
    // `staleMs: 1` leaves the liveness check as the only thing that can refuse.
    plantHeldLock({ pid: process.pid, ageMs: 5_000 });
    const err = errorFrom(() => withFileLock(file, () => 'entered', { timeoutMs: 50, staleMs: 1 }));
    expect(err).toBeInstanceOf(FileLockError);
    expect((err as FileLockError).reason).toBe('timeout');
    expect(existsSync(lock)).toBe(true);
  });

  it('takes a lock whose pid still resolves once it is far past any plausible hold', () => {
    // The liveness check's own failure mode: a dead holder's pid gets recycled by
    // an unrelated process, and a lock kept alive by that coincidence would never
    // be recoverable — the permanent wedge the stale path exists to prevent. Past
    // the abandon window the recycled-pid reading wins over the still-running one.
    plantHeldLock({ pid: process.pid, ageMs: 10 * 60_000 });
    expect(withFileLock(file, () => 'entered', { timeoutMs: 1_000, staleMs: 1_000 })).toBe(
      'entered',
    );
    expect(existsSync(lock)).toBe(false);
  });

  it('judges a lock from another host on age alone, since its pid is not ours to ask about', () => {
    // A ~/.aka on a shared network home carries locks from other machines, where
    // a pid names a process in someone else's table. Asking locally answers about
    // an unrelated program — so that answer must not be what keeps the lock.
    plantHeldLock({ pid: process.pid, ageMs: 5_000, host: 'some-other-machine' });
    expect(withFileLock(file, () => 'entered', { timeoutMs: 1_000, staleMs: 1_000 })).toBe(
      'entered',
    );
    expect(existsSync(lock)).toBe(false);
  });

  it('lets only one waiter recover a given abandoned lock', () => {
    // Several waiters meet one abandoned lock at the same moment. Unserialised
    // they all judge it stale, one removes it and takes a fresh lock, and the
    // next one's removal lands on THAT — two writers inside at once, which is
    // the defect the lock exists to remove. The recovery is serialised by its
    // own exclusive file so the second waiter re-reads the path and finds the
    // first one's live lock instead of the abandoned one.
    plantHeldLock({ pid: DEAD_PID, ageMs: 60_000 });

    // Stand in for the winner: hold the section, and from inside it let another
    // waiter judge the same lock this call already recovered.
    let inner: unknown;
    const outer = withFileLock(
      file,
      () => {
        inner = errorFrom(() =>
          withFileLock(file, () => 'second-in', { timeoutMs: 60, staleMs: 1 }),
        );
        return 'first-in';
      },
      { timeoutMs: 1_000, staleMs: 1_000 },
    );

    expect(outer).toBe('first-in');
    // The second waiter must be refused, not handed the section: the lock it
    // meets is the winner's live one, however stale the one it set out to break.
    expect(inner).toBeInstanceOf(FileLockError);
    expect(existsSync(lock)).toBe(false);
  });

  it('leaves no breaker file behind', () => {
    plantHeldLock({ pid: DEAD_PID, ageMs: 60_000 });
    withFileLock(file, () => 'entered', { timeoutMs: 1_000, staleMs: 1_000 });
    // A breaker left behind stalls every later recovery until it ages out.
    expect(readdirSync(dir)).toEqual([]);
  });

  it('does not delete a lock that was taken away from it', () => {
    // The cascade this guards: a holder that was stolen from must not remove the
    // lock its successor now holds. Unlinking by path alone does exactly that,
    // and the successor's successor then walks in while the successor is still
    // writing — every writer reporting success.
    let observed: string | undefined;
    withFileLock(file, () => {
      // Stand in for the thief: replace the lock with somebody else's while this
      // call is inside the section.
      writeFileSync(
        lock,
        `${JSON.stringify({ pid: process.pid, token: 'thief', at: Date.now() })}\n`,
      );
      observed = 'held';
    });
    expect(observed).toBe('held');
    // The thief's lock survives its predecessor's release.
    expect(existsSync(lock)).toBe(true);
    expect(JSON.parse(readFileSync(lock, 'utf8'))).toMatchObject({ token: 'thief' });
  });

  it('refuses an async body rather than releasing the lock before it finishes', async () => {
    // The lock is dropped when `fn` returns, so an async body would hand it back
    // at the first await with the write still to come — silently unguarded, and
    // type-checking clean. Refused instead.
    let settled: Promise<string> | undefined;
    expect(() =>
      withFileLock(file, () => {
        settled = Promise.resolve('done');
        return settled;
      }),
    ).toThrow(TypeError);
    await settled;
    // And the refusal still releases, rather than wedging the file.
    expect(existsSync(lock)).toBe(false);
  });

  it('measures staleness from the lock body, not the file mtime', () => {
    // An mtime comes from whichever clock owns the filesystem. On a network home
    // that is the server's, so a client a few seconds ahead would read every
    // fresh lock as already abandoned and exclusion would silently disappear.
    plantHeldLock({ pid: DEAD_PID, ageMs: 0 });
    backdate(lock, 10 * 60_000); // an mtime far outside any stale window
    const err = errorFrom(() =>
      withFileLock(file, () => 'entered', { timeoutMs: 50, staleMs: 2_000 }),
    );
    expect(err).toBeInstanceOf(FileLockError);
    expect(existsSync(lock)).toBe(true);
  });

  it('recovers a lock with an unreadable body, which records no clock or pid', () => {
    // A truncated write leaves a lock nothing can identify. Falling back to mtime
    // is what stops it wedging the file forever.
    writeFileSync(lock, 'not json at all');
    backdate(lock, 10_000);
    expect(withFileLock(file, () => 'entered', { timeoutMs: 1_000, staleMs: 1_000 })).toBe(
      'entered',
    );
    expect(existsSync(lock)).toBe(false);
  });

  it('does not take a lock younger than the stale window', () => {
    plantHeldLock({ pid: DEAD_PID, ageMs: 1_000 });
    // The stale path is a last resort for a dead holder. If it fired on a live
    // one it would hand the section to two writers at once — the exact defect
    // the lock exists to remove, reintroduced by its own recovery.
    expect(() => withFileLock(file, () => 'entered', { timeoutMs: 50, staleMs: 30_000 })).toThrow(
      FileLockError,
    );
    expect(existsSync(lock)).toBe(true);
  });

  it('creates the lock owner-only', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('POSIX modes are a no-op on Windows');
      return;
    }
    let mode = 0;
    withFileLock(file, () => {
      mode = statSync(lock).mode & 0o777;
    });
    expect(mode).toBe(0o600);
  });

  it('refuses to write through a symlink planted at the lock path', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('symlink creation needs a privilege this runner may not have');
      return;
    }
    // The lock sits in ~/.aka beside the file it guards, so in the loose-store
    // state this package exists to repair its path is as plantable as the tmp
    // path. The exclusive create is what refuses to follow the link — the same
    // property the atomic write depends on.
    const victimDir = join(dir, 'victim');
    mkdirSync(victimDir);
    const victim = join(victimDir, 'precious');
    writeFileSync(victim, 'untouched');
    symlinkSync(victim, lock);

    expect(() => withFileLock(file, () => 'entered', NEVER_STALE)).toThrow(FileLockError);
    expect(readFileSync(victim, 'utf8')).toBe('untouched');
    expect(lstatSync(lock).isSymbolicLink()).toBe(true);
  });

  it('serialises callers that arrive one after another', () => {
    // Not a race — a plain check that an ordinary sequence of writers still
    // makes progress, so a lock that never released would show up here rather
    // than only under contention.
    const order: number[] = [];
    for (let i = 0; i < 5; i++) withFileLock(file, () => order.push(i));
    expect(order).toEqual([0, 1, 2, 3, 4]);
  });
});

// Capture OUTSIDE the catch: a `try { …; throw new Error('expected') } catch`
// shape asserts on the test's own guard error, and stays green when the call
// under test stops throwing altogether.
function errorFrom(fn: () => unknown): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}
