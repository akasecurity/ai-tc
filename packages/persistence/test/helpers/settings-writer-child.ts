/**
 * One settings writer, as a process of its own — the shape the product runs in.
 *
 * The wizard, `aka init` and the dashboard server are three separate processes
 * over one ~/.aka, and the race between them is a FILE race, so neither
 * `withTwoWriters` (independent handles on one store, in one thread) nor a
 * worker thread models it. A worker would in fact model the wrong thing: it
 * shares `process.pid`, and the tmp path the atomic write builds is per-process,
 * so two threads meet a collision that two processes never can.
 *
 * Reports on stdout as one JSON line rather than by exit code, because the
 * interesting failure is a writer that reported success and lost its answer
 * anyway. The timestamps bracket the applyOnboarding call so a test can show the
 * writers really did overlap — a barrier that quietly serialised them would make
 * every no-loss assertion pass for the wrong reason.
 *
 * Loaded by Node directly, outside the test runner's transform, so it stays on
 * node: builtins and plain erasable type annotations.
 */
import { existsSync, writeFileSync, writeSync } from 'node:fs';

import { applyOnboarding } from '../../src/settings.ts';

const [base, jobJson, readyFile, goFile, barrierTimeoutArg, parentPidArg, readyToken] =
  process.argv.slice(2);
if (
  base === undefined ||
  jobJson === undefined ||
  readyFile === undefined ||
  goFile === undefined
) {
  throw new Error(
    'settings-writer-child: expected <base> <jobJson> <readyFile> <goFile> [barrierTimeoutMs] [parentPid] [readyToken]',
  );
}

/**
 * The ceiling on a parked writer's wait, used when the parent named none.
 *
 * Only a hand-run child reaches this — the harness always passes its own. It
 * exists because an invocation made outside the harness is exactly how this
 * file last left processes polling for a week, and it is deliberately the more
 * generous of the two: nothing is enforcing readiness on that path, so a person
 * driving it may take a while to create the release file.
 *
 * Its being DIFFERENT from the harness's value is also what makes the
 * pass-through observable. Were the two equal, a test reading the effective
 * timeout back could not tell a harness that passed one from a child that fell
 * back to this, and the harness's constant could stop being sent without
 * anything going red.
 */
const DEFAULT_BARRIER_TIMEOUT_MS = 120_000;

/** How often the park loop asks whether the parent is still there. */
const LIVENESS_POLL_MS = 50;

/** Exit code for a writer that gave up at the barrier without writing. */
const EXIT_ABANDONED = 3;

const requestedTimeout = Number(barrierTimeoutArg);
const barrierTimeoutMs =
  Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? requestedTimeout
    : DEFAULT_BARRIER_TIMEOUT_MS;

/**
 * The pid this writer was spawned by, as the SPAWNER named it.
 *
 * Told rather than observed, because `process.ppid` read here is already the
 * wrong answer whenever the parent died during this process's own boot: the
 * first read is then the ADOPTIVE parent, and comparing it against itself can
 * never fire — the orphan waits out its whole ceiling. That is not a corner
 * case; it is what a spawner that exits immediately after spawning does every
 * time, and it is how this check came to pass its unit test while leaving a
 * live orphan behind.
 *
 * Reading `process.ppid === 1` as "orphaned" instead would be wrong in a
 * container, where the runner legitimately IS pid 1 and every writer would
 * abandon at once. Falling back to the observed value keeps a hand-run child
 * working, where there is no spawner to ask.
 */
const requestedParentPid = Number(parentPidArg);
const PARENT_PID =
  Number.isInteger(requestedParentPid) && requestedParentPid > 0
    ? requestedParentPid
    : process.ppid;

/**
 * Whether the process that spawned this one has gone.
 *
 * Two checks, because neither covers both platforms. On POSIX a dead parent
 * gets this process REPARENTED, so `process.ppid` stops matching the pid above
 * — whether it changes while parked or was already different on the first read.
 * Windows never reparents, so there the ppid stays put and only the second
 * check can fire: signal 0 delivers nothing and merely asks whether the pid is
 * still live. `EPERM` means it exists but is not ours to signal, so only
 * `ESRCH` counts as gone.
 *
 * A recycled pid reads as "still there", which costs nothing: the deadline
 * below is the guarantee, and this is only the fast path to it.
 */
function parentIsGone(): boolean {
  if (process.ppid !== PARENT_PID) return true;
  try {
    process.kill(PARENT_PID, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'ESRCH';
  }
}

/**
 * Leave the barrier without writing, and say why on stderr.
 *
 * `writeSync` rather than `process.stderr.write`, because stderr is a pipe here
 * and `process.exit` does not flush a pending pipe write — the reason would be
 * truncated or lost exactly when the harness needs it to explain a non-zero
 * exit.
 */
function abandon(reason: string): never {
  writeSync(2, `settings-writer-child: ${reason}\n`);
  process.exit(EXIT_ABANDONED);
}

const job = JSON.parse(jobJson) as { set?: Record<string, unknown>; clear?: string[] };

// `clear` is a list of names rather than keys set to undefined, because
// JSON.stringify DROPS an undefined value: a revoke written the natural way
// crosses as `{}` and the child writes nothing at all. Silently — the writer
// still reports success, so a test asserting the revoke stuck fails looking like
// a product defect, and one asserting the grant survived passes for no reason.
const answers: Record<string, unknown> = { ...job.set };
for (const field of job.clear ?? []) answers[field] = undefined;

// A handshake, not a clock. Announce that this process is loaded and ready, then
// wait until the parent releases everyone. A deadline-based barrier instead ties
// the contention to how long Node takes to boot and load the schema — which
// under a full parallel suite can outlast the deadline, leaving the writers to
// run one after another and every no-loss assertion true for want of a race.
//
// Polled with a sleep rather than a bare spin: several of these run at once,
// and a hot loop each would take a core apiece off the rest of the suite —
// enough to push a timing-sensitive test elsewhere over its threshold. The
// extra millisecond of release latency costs nothing here, since the barrier's
// assertion tolerates a late start (see barrierReport).
//
// The wait is bounded, but NOT by a clock standing in for the handshake. The
// distinction is the whole point: a deadline-based barrier expires and lets the
// writer RUN, which is the silently-serialised run described above. These two
// exits abandon the run instead — the child writes nothing and exits non-zero,
// and the harness turns that into a failed run rather than an outcome. So they
// can only ever cost a real failure its speed, never buy a fake pass.
//
// Both are checked inside this loop rather than on the event loop, because the
// loop is synchronous: an `exit` handler, an `unref`'d timer or a stdin EOF
// would all sit unrun until the barrier lifted, which is precisely when they
// are no longer needed.
const PARK = new Int32Array(new SharedArrayBuffer(4));
// How long this process took to get here — a DURATION, measured against this
// process's own start, so it carries no instant the parent could be tempted to
// compare against one of its own. That comparison is what this harness was last
// fixed for.
const bootMs = performance.now();
// Local-only, and compared against this process's own Date.now() below. It is
// not reported: an instant that crossed the boundary is what the parent used to
// mis-compare against its own.
const parkedAt = Date.now();
const barrierDeadline = parkedAt + barrierTimeoutMs;
let nextLivenessCheck = parkedAt + LIVENESS_POLL_MS;
// The token names WHICH writer this is, so the parent counts a ready file only
// against the writer that wrote it. Mere existence would let one writer's file
// satisfy every index if the paths were ever shared, releasing the barrier
// while the rest were still booting.
writeFileSync(readyFile, readyToken ?? '');
while (!existsSync(goFile)) {
  const now = Date.now();
  if (now >= barrierDeadline) {
    abandon(`no release after ${String(barrierTimeoutMs)}ms at the barrier`);
  }
  // Throttled: the parent is nearly always alive, and the harness runs one of
  // these per job. Probing every millisecond alongside the existsSync would add
  // a syscall per writer per millisecond to a wait that legitimately lasts as
  // long as the slowest sibling takes to boot.
  if (now >= nextLivenessCheck) {
    nextLivenessCheck = now + LIVENESS_POLL_MS;
    if (parentIsGone()) abandon('parent exited before releasing the barrier');
  }
  Atomics.wait(PARK, 0, 0, 1);
}

const startedAt = Date.now();
let ok = false;
let error: string | undefined;
try {
  applyOnboarding(answers, base);
  ok = true;
} catch (err) {
  error = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}
// `barrierTimeoutMs` is reported back so a test can show the harness really
// passed one. Left to the default it would be dead configuration: the bound
// would still hold, but at a value nothing in the harness chose.
process.stdout.write(
  `${JSON.stringify({ ok, error, bootMs, startedAt, endedAt: Date.now(), barrierTimeoutMs })}\n`,
);
