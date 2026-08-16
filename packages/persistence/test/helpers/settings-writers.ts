/**
 * N concurrent settings writers, each in its own process, released together.
 *
 * `withTwoWriters` deliberately does not cover this: it hands out independent
 * SQLite handles in ONE thread, and `node:sqlite` is synchronous, so those
 * interleave rather than collide. settings.json is outside SQLite entirely —
 * no WAL, no `busy_timeout` — and its writers are separate processes, so the
 * contention has to be real.
 */
import type { ChildProcess } from 'node:child_process';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const CHILD = fileURLToPath(new URL('./settings-writer-child.ts', import.meta.url));

/** How long to wait for every writer to report itself loaded and ready. */
const READY_TIMEOUT_MS = 30_000;

/**
 * The ceiling on how long a parked writer waits to be released.
 *
 * Derived from the readiness timeout rather than chosen, because a legitimate
 * wait at the barrier is exactly the time the SLOWEST sibling takes to boot,
 * which is what `READY_TIMEOUT_MS` already bounds. Doubling it leaves the
 * failsafe unreachable on any run this helper would not already have failed,
 * so it can only ever fire on a parent that stopped releasing at all.
 */
const BARRIER_TIMEOUT_MS = READY_TIMEOUT_MS * 2;

/**
 * Every writer spawned by this process and not yet reaped.
 *
 * A run's own `finally` covers every path the event loop reaches. This covers
 * the one it does not: the runner tearing this process down mid-run — a suite
 * timeout, a `--bail`, a failed sibling file — which leaves a child parked at
 * the barrier to be reparented and poll on. That is how this helper's children
 * were last found still running a week later. The child's own barrier deadline
 * bounds it regardless; this ends it at once when the teardown is graceful
 * enough to run exit handlers at all.
 */
const liveWriters = new Set<ChildProcess>();

process.on('exit', () => {
  for (const child of liveWriters) child.kill('SIGKILL');
});

/** What one writer applies. */
export interface WriterJob {
  /** Fields to set, with the values to set them to. */
  set?: Record<string, unknown>;
  /**
   * Fields to clear — a revoke.
   *
   * Named rather than passed as `undefined` values because JSON.stringify drops
   * an undefined, so a revoke would cross the process boundary as an empty
   * answer set and the writer would apply nothing while still reporting success.
   */
  clear?: string[];
}

/** One writer's own account of its write. */
export interface WriterOutcome {
  /** Whether applyOnboarding returned. */
  ok: boolean;
  /** `Name: message` when it threw; absent when it returned. */
  error?: string;
  /**
   * When this writer finished loading and parked at the barrier, on ITS clock.
   *
   * Diagnostic only — it says how long this writer took to boot, which is worth
   * having when a run fails. It is not comparable with anything stamped by the
   * parent; `ConcurrentRun.readyObservedAt` is the parent-clock counterpart the
   * barrier check reads.
   */
  readyAt: number;
  startedAt: number;
  endedAt: number;
  /**
   * The barrier ceiling this writer actually ran under.
   *
   * Reported back so a test can show the harness passed one, rather than the
   * child having fallen back to its own default — under which the bound still
   * holds, but at a value nothing here chose.
   */
  barrierTimeoutMs: number;
}

/** One concurrent run: what each writer reported, and when they were released. */
export interface ConcurrentRun {
  outcomes: WriterOutcome[];
  /** The instant the parent released every parked writer. */
  releasedAt: number;
  /**
   * When THIS process first saw each writer's ready file, by writer index, and
   * `undefined` for one it never saw park at all.
   *
   * Stamped here rather than taken from the writer's own `readyAt` because the
   * barrier check compares these against `releasedAt`, and two stamps only
   * order each other when one clock took them both. See allReleasedTogether.
   */
  readyObservedAt: (number | undefined)[];
}

interface Writer {
  child: ChildProcess;
  done: Promise<ChildResult>;
}

interface ChildResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function spawnWriter(base: string, job: WriterJob, readyFile: string, goFile: string): Writer {
  const child = spawn(
    process.execPath,
    [
      CHILD,
      base,
      JSON.stringify(job),
      readyFile,
      goFile,
      String(BARRIER_TIMEOUT_MS),
      // Named, not left for the child to observe: if this process dies while
      // the child is still booting, the child's own first read of `ppid` is
      // already the adoptive parent and its liveness check can never fire.
      String(process.pid),
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  liveWriters.add(child);
  const done = new Promise<ChildResult>((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.on('error', (err) => {
      liveWriters.delete(child);
      reject(err);
    });
    child.on('close', (code) => {
      liveWriters.delete(child);
      resolve({ code, stdout, stderr });
    });
  });
  return { child, done };
}

// Poll until every writer has announced itself, or give up loudly, and report
// WHEN each one was seen — on this process's clock, which is also the clock that
// stamps the release.
//
// A silent give-up would release the ones that are ready and leave the rest to
// arrive afterwards — the serialised run this handshake exists to rule out. A
// writer that DIED is the other way to wait forever, so an exited child ends the
// wait at once rather than at the timeout: its readiness is never coming, and
// the caller has a real failure to report. It returns what it saw either way,
// so a writer left unobserved is visible as a gap rather than inferred from a
// timestamp that never arrived.
async function waitForAllReady(
  writers: Writer[],
  readyFiles: string[],
): Promise<(number | undefined)[]> {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  const observedAt: (number | undefined)[] = readyFiles.map(() => undefined);
  const seen = (): boolean => observedAt.every((at) => at !== undefined);
  // Stamped on the first pass that finds each file, not once at the end: a
  // single stamp for the whole set would say when the LAST writer parked and
  // claim it for every one of them.
  const sweep = (): void => {
    readyFiles.forEach((f, i) => {
      if (observedAt[i] === undefined && existsSync(f)) observedAt[i] = Date.now();
    });
  };
  sweep();
  while (!seen()) {
    if (writers.some((w) => w.child.exitCode !== null || w.child.signalCode !== null)) {
      return observedAt;
    }
    if (Date.now() >= deadline) {
      const missing = observedAt.filter((at) => at === undefined).length;
      throw new Error(
        `${String(missing)} of ${String(readyFiles.length)} settings writers never reported ready`,
      );
    }
    await delay(5);
    sweep();
  }
  return observedAt;
}

/**
 * Run one writer per job, all released at the same instant, and return what each
 * one reported.
 *
 * THROWS on a child that died or printed nothing parseable, rather than folding
 * it into a `false`. A crashed writer wrote nothing, so every "no answer was
 * lost" assertion downstream would pass on a run where most of the writers never
 * ran — the failure this helper exists to make visible, arriving as a green
 * test. The child's stderr is carried into the message, because a module that
 * failed to load says so there and nowhere else.
 */
export async function runConcurrentSettingsWriters(
  base: string,
  jobs: WriterJob[],
): Promise<ConcurrentRun> {
  const sync = mkdtempSync(join(tmpdir(), 'aka-writer-sync-'));
  const goFile = join(sync, 'go');
  const readyFiles = jobs.map((_, i) => join(sync, `ready-${String(i)}`));
  // Declared outside the try so the cleanup can reach them. A writer parks by
  // polling for `goFile`, so a throw that removed the sync dir without killing
  // the children would leave them waiting on a path that can never appear —
  // orphans polling for the life of the CI job.
  const writers = jobs.map((job, i) => spawnWriter(base, job, readyFiles[i] ?? '', goFile));
  let results: ChildResult[];
  let releasedAt: number;
  let readyObservedAt: (number | undefined)[];
  try {
    readyObservedAt = await waitForAllReady(writers, readyFiles);
    // Released only once every writer is loaded and waiting. Timing the barrier
    // instead ties the contention to Node's boot time, which under a full
    // parallel suite can outrun any deadline — and a barrier that expired early
    // does not fail, it just serialises the writers, leaving every no-loss
    // assertion downstream true for want of a race.
    releasedAt = Date.now();
    writeFileSync(goFile, '');
    results = await Promise.all(writers.map((w) => w.done));
  } finally {
    // Unconditional, and ahead of the sync dir going: a writer parks by polling
    // for goFile, so removing that directory while one is still waiting leaves
    // it polling a path that can never appear. On the success path every child
    // has already exited and both calls are no-ops — which is what lets this be
    // one path rather than a catch that has to be kept in step with it.
    //
    // It reaches every way OUT of the try. It cannot reach a teardown that never
    // runs it at all; that case is the exit sweep above, and behind it the
    // child's own barrier deadline.
    for (const w of writers) w.child.kill('SIGKILL');
    await Promise.allSettled(writers.map((w) => w.done));
    rmSync(sync, { recursive: true, force: true });
  }
  const outcomes = results.map((result, index) => {
    if (result.code !== 0) {
      throw new Error(
        `settings writer ${String(index)} exited ${String(result.code)}: ${result.stderr.trim()}`,
      );
    }
    const line = result.stdout.trim();
    try {
      return JSON.parse(line) as WriterOutcome;
    } catch {
      throw new Error(
        `settings writer ${String(index)} printed no outcome (stdout: ${JSON.stringify(line)}, stderr: ${result.stderr.trim()})`,
      );
    }
  });
  return { outcomes, releasedAt, readyObservedAt };
}

/**
 * Whether every writer was already parked at the barrier before ANY of them was
 * released — the barrier's own positive control.
 *
 * The point of a barrier is contention, and one that quietly stopped working
 * would let each writer run as it finished booting, one after another. Every
 * no-loss assertion downstream then holds for want of a race, silently.
 *
 * It reads the PARENT's observations — the instant this process saw each ready
 * file — against the instant this process released them. Both stamps come off
 * one clock, which is what makes the comparison mean anything.
 *
 * It used to compare the child's own `readyAt` against `releasedAt`, and that
 * is a cross-process comparison: two processes stamping `Date.now()` are asking
 * two independently-maintained clocks, and on Windows those disagree by a few
 * milliseconds routinely. The causal order was never in doubt — a child stamps
 * `readyAt` BEFORE writing the file the parent then waits for — so a run this
 * check failed was one where the clocks disagreed, not one where the barrier
 * did. It reddened main from a genuinely green tree. The child's `readyAt` is
 * still reported, for reading a slow boot out of a failure; do not decide the
 * barrier on it again.
 *
 * The file is the evidence, not the timestamp, and it is evidence of the whole
 * property: the ready file exists only because the child wrote it on its way
 * into the park loop. So requiring one observation per writer, all of them
 * before the release, is the handshake itself. Delete the handshake and there
 * are no observations; break it so it waits for only the first writer, or
 * returns early on a child that died, and the gaps are what this reads.
 *
 * What it deliberately does NOT assert is that the calls overlapped in wall
 * clock. A released child can be descheduled — on a runner with more test
 * processes than cores, for longer than another writer's whole call — so an
 * overlap check fails on a scheduling artifact rather than on a defect.
 */
export function allReleasedTogether(run: ConcurrentRun): boolean {
  if (run.outcomes.length === 0) return false;
  // Per WRITER, not merely as many observations as writers: a run that saw one
  // writer park twice would otherwise count as a full set.
  if (run.readyObservedAt.length !== run.outcomes.length) return false;
  return run.readyObservedAt.every((at) => at !== undefined && at <= run.releasedAt);
}
