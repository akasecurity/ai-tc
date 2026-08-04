import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { hostname } from 'node:os';

import { DATA_FILE_MODE } from './paths.ts';

// Cross-process mutual exclusion around one file under ~/.aka.
//
// The plugin, the CLI and the dashboard are three independent processes over
// one home, and an atomic write is not enough on its own: tmp+rename makes each
// PUBLISH indivisible, but a read-modify-write spans two of them, so two writers
// can read the same bytes and the second rename silently discards the first
// one's change. `busy_timeout` covers none of this — settings.json and the key
// files are outside SQLite entirely.
//
// The lock is the EXISTENCE of a sibling `<file>.lock`, taken with an exclusive
// create. That is the one primitive every platform this ships to agrees on:
// `flock` has no Windows equivalent, and an advisory lock held on an fd is lost
// by any writer that opens the file a second time.

// A sibling of the file it guards, so it inherits the directory's 0700 and
// needs no layout of its own.
const LOCK_SUFFIX = '.lock';

// How long a writer waits for its turn. A legitimate hold is a single small
// read plus a write — sub-millisecond — so this is a ceiling on a queue that
// should never form, not a budget anything is expected to spend. It is not on
// any hook path: readWorkspaceSettings takes no lock, and the writers are the
// /aka:setup wizard, `aka init` and the dashboard's Settings save.
const DEFAULT_TIMEOUT_MS = 5_000;

// How old a lock must be before a waiter considers taking it. Reaching this
// alone is not enough — the recorded pid must also be gone (see breakIfStale),
// so a holder that is merely slow is waited for rather than evicted.
//
// Deliberately BELOW the acquire timeout: a waiter must be able to recover a
// dead holder's lock within its own call, rather than failing and leaving the
// next caller to meet the same lock.
const DEFAULT_STALE_MS = 2_000;

// Poll interval while another writer holds the lock. Short enough that a handoff
// is not the dominant cost of a write, long enough not to spin a core.
const RETRY_INTERVAL_MS = 5;

// Errnos that mean "try again", not "this can never work". EEXIST is a held
// lock. The rest are Windows: a deleted name stays in a delete-pending state
// until every handle closes and answers ERROR_ACCESS_DENIED (EACCES/EPERM), and
// a scanner or indexer holding the file answers ERROR_SHARING_VIOLATION (EBUSY)
// — all three transient, all three raised by an ordinary handoff. Whether one is
// contention or a directory that will never hold a lock is then decided by
// whether the lock path EXISTS, not by the errno.
const RETRYABLE_CREATE_ERRNOS = new Set(['EEXIST', 'EACCES', 'EPERM', 'EBUSY']);

// A block of shared memory nothing ever notifies, so `Atomics.wait` on it always
// runs to its timeout — the one way to sleep without yielding to the event loop.
// The callers here are synchronous top to bottom (the whole store API is), so
// an async sleep would mean making every writer async up to its entry point.
const PARK = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  Atomics.wait(PARK, 0, 0, ms);
}

export interface FileLockOptions {
  /** How long to wait for the lock before failing. */
  timeoutMs?: number;
  /** How old a lock must be, with its holder gone, before a waiter takes it. */
  staleMs?: number;
}

/**
 * Why the lock could not be taken.
 *
 * `timeout` is contention — somebody holds it and did not let go in time.
 * `unavailable` is the directory refusing to hold a lock at all (read-only,
 * unwritable, immutable), which no amount of waiting resolves.
 *
 * They are separated because reporting one as the other misleads in the
 * direction a user acts on: a permissions fault announced as "timed out waiting"
 * sends someone looking for a process that does not exist. `aka init` branches
 * on it — it repairs stores in the second state, while a contended lock means
 * another writer is mid-write and there is nothing for it to do.
 */
export type FileLockFailure = 'timeout' | 'unavailable';

/**
 * Raised when the lock could not be taken — a loud failure in place of the
 * silent overwrite this exists to prevent.
 *
 * Carries the holder's pid on a `timeout` when the lock file could be read, so a
 * writer wedged for seconds can be told apart from a lock file nothing owns.
 */
export class FileLockError extends Error {
  readonly reason: FileLockFailure;
  readonly file: string;
  readonly holderPid: number | undefined;
  constructor(
    reason: FileLockFailure,
    file: string,
    detail: string,
    holderPid?: number,
    options?: { cause?: unknown },
  ) {
    super(
      `cannot lock ${file} for writing: ${detail}` +
        (holderPid === undefined ? '' : ` (held by pid ${String(holderPid)})`),
      options,
    );
    this.name = 'FileLockError';
    this.reason = reason;
    this.file = file;
    this.holderPid = holderPid;
  }
}

// What a holder records in its lock file.
//
// `at` is the acquiring process's own clock, and staleness is measured from it
// rather than from the file's mtime. An mtime comes from whichever clock owns
// the filesystem — a server's, on the network homes this store already ships to
// — so a client running a couple of seconds ahead reads every lock as born
// stale and mutual exclusion silently disappears, while one running behind never
// recovers an abandoned lock at all. Coarse mtime granularity (2s on FAT/exFAT,
// 1s on ext3/HFS+) pushes the same way for free.
//
// `token` is what makes a release safe — see release().
//
// `host` is what makes the pid meaningful. A `~/.aka` on a network home is
// shared between machines, where a pid names a process in someone else's table:
// asking about it locally answers about an unrelated program, so a lock from
// another host is judged on age alone.
interface LockBody {
  pid: number;
  token: string;
  at: number;
  host: string;
}

function lockPathFor(file: string): string {
  return `${file}${LOCK_SUFFIX}`;
}

// The body of the lock currently at `lock`. Null covers both "no file" and "not
// a body this understands" — a truncated write, or a file another tool left at
// the path — which the callers treat differently, so neither may be mistaken for
// a readable body.
function readLockBody(lock: string): LockBody | null {
  let raw: string;
  try {
    raw = readFileSync(lock, 'utf8');
  } catch {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    const { pid, token, at, host } = parsed as Partial<LockBody>;
    if (typeof pid !== 'number' || typeof token !== 'string' || typeof at !== 'number') return null;
    return { pid, token, at, host: typeof host === 'string' ? host : '' };
  } catch {
    return null;
  }
}

// Whether the process that recorded the lock is still running here. `kill(pid, 0)`
// sends no signal, it only asks; EPERM means the process exists under another
// user, which is still alive.
//
// Answers `true` when it cannot tell, because the safe direction is to leave a
// lock alone: waiting costs a timeout the caller reports, where stealing from a
// live holder puts two writers in the section — the defect this module exists to
// remove.
function holderIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

// Take the lock, returning the token that proves this call owns it, or null if
// somebody else holds it.
//
// `wx` is O_CREAT|O_EXCL: it succeeds for exactly one caller, and it REFUSES to
// follow a symlink, so a link planted at the lock path can never be written
// through — the same property the tmp write in paths.ts relies on.
//
// A create that fails for a retryable reason is contention only if a lock is
// actually there. With no file at the path the fault is the directory's, and no
// amount of waiting fixes a read-only or immutable one, so it is raised at once
// rather than spending the whole timeout to report contention that never was.
function tryAcquire(lock: string, file: string): string | null {
  const token = randomUUID();
  let fd: number;
  try {
    fd = openSync(lock, 'wx', DATA_FILE_MODE);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? '';
    // EEXIST is unambiguous — the file was there — and needs no second opinion.
    // Asking `existsSync` about it as well would call a normal handoff
    // permanent: the holder can release between the two calls, leaving a
    // released lock reported as a directory that will never hold one, with an
    // EEXIST message attached. That fires on an ordinary two-writer handoff.
    if (code === 'EEXIST') return null;
    // The rest arrive from Windows for both reasons, so the path itself decides:
    // a lock that is there is contention, and one that is not means the
    // directory refused the create.
    if (RETRYABLE_CREATE_ERRNOS.has(code) && existsSync(lock)) return null;
    throw new FileLockError(
      'unavailable',
      file,
      err instanceof Error ? err.message : String(err),
      undefined,
      { cause: err },
    );
  }
  const body: LockBody = { pid: process.pid, token, at: Date.now(), host: hostname() };
  try {
    writeFileSync(fd, `${JSON.stringify(body)}\n`);
  } catch {
    // The body is what a waiter reads to decide staleness and ownership, so a
    // lock without one can never be identified as abandoned. Drop it rather than
    // leave behind one that nothing can recover.
    try {
      closeSync(fd);
    } catch {
      // fall through to the unlink; the file is what matters, not the handle
    }
    rmSync(lock, { force: true });
    return null;
  }
  try {
    closeSync(fd);
  } catch {
    // The fd is not the lock; the file is. Nothing here can un-take it.
  }
  return token;
}

// Whether a lock is abandoned: older than `staleMs` by its OWN recorded clock,
// and written by a process that is gone. Age alone evicts a holder that is
// merely slow — a suspended laptop, a throttled container, a network home — and
// puts two writers in the section.
function isAbandoned(body: LockBody | null, lock: string, staleMs: number): boolean {
  if (!body) {
    // A lock with no readable body records neither a clock nor a pid — a
    // truncated write, or a file another tool left at this path. Fall back to the
    // filesystem's mtime so it can still be recovered rather than wedging the
    // file forever; there is no pid to ask about.
    try {
      return Date.now() - statSync(lock).mtimeMs >= staleMs;
    } catch {
      return false;
    }
  }
  if (Date.now() - body.at < staleMs) return false;
  // A pid is only answerable on the host that recorded it. On a shared network
  // home it names a process in another machine's table, where a local answer is
  // about an unrelated program, so those are judged on age alone.
  if (body.host !== hostname() || !holderIsAlive(body.pid)) return true;
  // Past the abandon window a still-resolving pid is read as recycled: a dead
  // holder's number gets reused, and an unrelated process wearing it would
  // otherwise keep the lock alive forever — the permanent wedge the stale path
  // exists to prevent, reintroduced by its own liveness check.
  return Date.now() - body.at >= abandonWindow(staleMs);
}

// Hand a waiter the lock of a process that died holding it.
//
// The judging and the removal are ONE critical section, held against the other
// waiters by a second exclusive file. That is what makes the removal safe rather
// than merely likely: several waiters meet the same abandoned lock at once, and
// unserialised they all judge it stale, then one removes it and takes a fresh
// lock while the next one's removal lands on THAT — so two of them end up inside
// the section, which is the defect the lock exists to remove. Neither a rename
// nor a re-read closes it, because every check is separated from its removal by
// a window another waiter can act in.
//
// Serialised, the second waiter re-reads the path inside the breaker and finds
// the first one's fresh, live lock instead of the abandoned one, so it simply
// waits.
function breakIfStale(lock: string, staleMs: number): boolean {
  const breaker = `${lock}.break`;
  let fd: number;
  try {
    fd = openSync(breaker, 'wx', DATA_FILE_MODE);
  } catch {
    // Another waiter is judging right now — its outcome is the one that counts,
    // so this call just waits. A breaker left behind by a killed waiter is reaped
    // rather than blocking every future recovery.
    reapAbandonedBreaker(breaker);
    return false;
  }
  try {
    closeSync(fd);
  } catch {
    // The fd is not the breaker; the file is.
  }
  try {
    // Re-read INSIDE the section. The lock this call meant to judge may already
    // have been recovered, and what sits at the path now can be a live holder.
    if (!existsSync(lock) || !isAbandoned(readLockBody(lock), lock, staleMs)) return false;
    // Safe to remove by path: the lock is here, so nobody can be acquiring; its
    // holder is gone, so nobody is releasing; and no other waiter can be
    // removing, because this call holds the breaker.
    rmSync(lock, { force: true });
    return true;
  } catch {
    return false;
  } finally {
    try {
      rmSync(breaker, { force: true });
    } catch {
      // Left behind, and reaped by the next waiter that meets it.
    }
  }
}

// A breaker is held for the length of one read and one unlink, so anything that
// has sat around is a waiter that died mid-judgement. Reaped on mtime alone —
// there is no body and no holder to ask about, and leaving it would disable
// recovery for the file permanently.
const BREAKER_ABANDONED_MS = 10_000;

function reapAbandonedBreaker(breaker: string): void {
  try {
    if (Date.now() - statSync(breaker).mtimeMs >= BREAKER_ABANDONED_MS) {
      rmSync(breaker, { force: true });
    }
  } catch {
    // Gone already, or unreadable — the next waiter tries again.
  }
}

// How long past `staleMs` a lock whose pid still resolves is tolerated before it
// is taken anyway. Generous, because inside it a genuinely slow holder is safe;
// past it the likeliest explanation is a recycled pid, and the alternative is a
// file no writer can ever have again.
function abandonWindow(staleMs: number): number {
  return Math.max(staleMs * 30, 60_000);
}

// Drop the lock, but ONLY while the file still carries this call's token.
//
// A holder that was stolen from must not delete the lock the thief now holds.
// Unlinking by path alone does exactly that, and it cascades: the thief's
// successor is let in while the thief is still writing, which is the lost update
// the lock exists to prevent, now with every writer reporting success.
//
// Best-effort and deliberately never throwing: a release that failed must not
// mask the outcome of the work it guarded. A lock left behind is recovered by
// the stale path above rather than wedging the file.
// A body that cannot be read is NOT this call's lock either. Falling through to
// an unlink there defeats the whole guard in the one window a successor is most
// exposed: a fresh lock exists for an instant between its exclusive create and
// its body write, so a departing predecessor would find no body and delete it.
// A lock this call does not own is left for the stale path to recover.
function release(lock: string, token: string): void {
  try {
    if (readLockBody(lock)?.token !== token) return;
    rmSync(lock, { force: true });
  } catch {
    // see above
  }
}

/**
 * Run `fn` as the only writer of `file` on this machine.
 *
 * Guards a read-modify-write, which tmp+rename cannot: rename makes each publish
 * indivisible, but two writers that both read before either renames still lose
 * one side's change. Every writer of a given file must take this lock — it is
 * advisory, so a writer that skips it is not excluded by the ones that do.
 *
 * The caller must have created the parent directory (ensureDataDirSync): the
 * lock is a sibling of `file`.
 *
 * NOT re-entrant. A nested call on the same file waits out its own timeout and
 * throws, because the outer hold belongs to a live process this one cannot tell
 * apart from any other holder — and must not, or it would steal from itself.
 *
 * `fn` must be SYNCHRONOUS. The lock is released when `fn` returns, so an async
 * body would drop it at the first await with the write still to come; that is
 * refused rather than left silently unguarded.
 *
 * Throws {@link FileLockError} rather than proceeding unlocked when the lock
 * cannot be taken. Losing a write loudly is recoverable — the user is told and
 * retries — where losing it silently is not, and the fields at stake include the
 * consent grants a user can revoke.
 */
export function withFileLock<T>(file: string, fn: () => T, options: FileLockOptions = {}): T {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;
  const lock = lockPathFor(file);
  const deadline = Date.now() + timeoutMs;

  let token = tryAcquire(lock, file);
  while (token === null) {
    // A successful steal is retried at once rather than slept on, and BEFORE the
    // deadline is consulted: the lock is gone, so failing here would report a
    // timeout for a section this call had just cleared for itself.
    if (breakIfStale(lock, staleMs)) {
      token = tryAcquire(lock, file);
      continue;
    }
    if (Date.now() >= deadline) {
      throw new FileLockError(
        'timeout',
        file,
        `still held after ${String(timeoutMs)}ms`,
        readLockBody(lock)?.pid,
      );
    }
    sleepSync(RETRY_INTERVAL_MS);
    token = tryAcquire(lock, file);
  }

  try {
    const result = fn();
    if (isThenable(result)) {
      // The body has already started; nothing here can call it back. Adopt its
      // rejection so a failure inside it cannot become an unhandled rejection —
      // which under Node's default policy takes the whole process down, and the
      // processes reachable here include the dashboard server.
      void (result as PromiseLike<unknown>).then(
        () => undefined,
        () => undefined,
      );
      throw new TypeError(
        `withFileLock(${file}) was given an async body; the lock is released as soon as it ` +
          'returns, so the awaited work would run unguarded. Pass a synchronous function.',
      );
    }
    return result;
  } finally {
    release(lock, token);
  }
}

function isThenable(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}
