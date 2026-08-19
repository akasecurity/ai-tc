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
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

/**
 * A file's contents, or `undefined` when it is not there yet.
 *
 * Only ENOENT is absence. Anything else — a permission fault, a Windows sharing
 * violation — is a real fault and is raised, rather than being folded into "not
 * ready" and waited out until the deadline reports the wrong diagnosis.
 */
function readFileIfPresent(file: string): string | undefined {
  try {
    return readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw err;
  }
}

const CHILD = fileURLToPath(new URL('./settings-writer-child.ts', import.meta.url));

/**
 * How long to wait for every writer to report itself loaded and ready.
 *
 * Deliberately UNDER this package's 20s `testTimeout`, so the give-up below is
 * the thing that fails the run. At 30s it could never fire: vitest won the race
 * every time and a run where writers failed to boot died on a bare
 * `Test timed out in 20000ms`, naming neither the count nor which ones were
 * missing. Same trap CLAUDE.md records for the PATH shim's probe deadline.
 *
 * The headroom is still large. Seven writers boot in ~200ms locally, and
 * CLAUDE.md measures this package's CI factor at ~30x, so this is roughly two
 * orders of magnitude clear of a legitimate wait. Raising it past the
 * `testTimeout` buys nothing and costs the diagnosis.
 */
const READY_TIMEOUT_MS = 15_000;

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
   * How long this writer took to load and reach the barrier, in ms.
   *
   * A DURATION, measured child-locally, where this used to be a `readyAt`
   * instant. An instant invites the comparison this whole file exists to
   * retire — the parent has instants of its own, and nothing in the type said
   * they were incomparable — so the misuse is now unexpressible rather than
   * forbidden by a comment. `barrierReport` quotes it when a writer is late or
   * missing, which is the case where "this one took 4s to boot" is the answer.
   */
  bootMs: number;
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
  /**
   * When the parent released every parked writer, on `performance.now()`.
   *
   * Monotonic, and that is load-bearing rather than tidy. One clock is
   * necessary but not sufficient: `Date.now()` steps BACKWARDS on an NTP
   * correction or a VM host time sync, and CI runners are VMs — so a resync
   * landing between the last sweep and this stamp reads an observation as later
   * than the release and reddens a run whose barrier held. That is the same
   * failure this file was opened to fix, merely rarer. Both stamps are
   * in-process and compared only to each other, so nothing here needs a wall
   * clock at all.
   */
  releasedAt: number;
  /**
   * When THIS process first saw each writer's ready token, by writer index, and
   * `undefined` for one it never saw park at all.
   *
   * On the same monotonic clock as `releasedAt`, which is what makes the
   * comparison mean anything. The resolution is one poll interval, so writers
   * that park inside the same 5ms gap share a stamp — these order writers
   * against the RELEASE, and are not a per-writer boot measurement. `bootMs` is
   * that.
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

function spawnWriter(
  base: string,
  job: WriterJob,
  readyFile: string,
  goFile: string,
  token: string,
): Writer {
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
      token,
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

/**
 * What a writer must have written into its ready file for the parent to count
 * it — the writer's own index, as the PARENT numbered it.
 *
 * Mere existence is not enough, and the difference is not theoretical. Point
 * every writer at one shared path — a plausible simplification of the
 * `ready-${i}` construction, or a bad merge — and writer 0's file satisfies
 * every index the moment it lands: the parent releases while the rest are still
 * booting, which is exactly the serialised run the barrier rules out, and the
 * observations come back full and in order so nothing downstream notices.
 *
 * Reading the index back is what makes the check independent again. The parent
 * is no longer taking its own word for having waited; the evidence is a byte
 * sequence only THAT child could have written, and it crosses the process
 * boundary without a clock, which is the whole point of this file.
 */
function readyToken(index: number): string {
  return `writer-${String(index)}`;
}

/**
 * Poll until every writer has announced ITSELF, or give up loudly, reporting
 * when each one was seen — on this process's monotonic clock, which is also the
 * clock that stamps the release.
 *
 * A silent give-up would release the ones that are ready and leave the rest to
 * arrive afterwards — the serialised run this handshake exists to rule out. A
 * writer that DIED is the other way to wait forever, so an exited child ends the
 * wait at once rather than at the timeout: its readiness is never coming, and
 * the caller has a real failure to report.
 *
 * A ready file whose token does not match yet counts as not-ready and is polled
 * again, which also covers the harmless race of reading one mid-write.
 */
async function waitForAllReady(
  writers: Writer[],
  readyFiles: string[],
): Promise<(number | undefined)[]> {
  const deadline = performance.now() + READY_TIMEOUT_MS;
  const observedAt: (number | undefined)[] = readyFiles.map(() => undefined);
  // One loop with one sweep site. Two sweep calls — one before the loop, one at
  // the foot of it — is a shape that drifts: deleting either is silent, since
  // the only effect is shifting every observation by one poll interval and no
  // assertion here reads an interval.
  for (;;) {
    readyFiles.forEach((f, i) => {
      if (observedAt[i] !== undefined) return;
      // A token that is not this writer's leaves the slot empty, so a shared or
      // crossed ready path times out below rather than passing as a full set.
      if (readFileIfPresent(f)?.trim() === readyToken(i)) observedAt[i] = performance.now();
    });
    if (observedAt.every((at) => at !== undefined)) return observedAt;
    if (writers.some((w) => w.child.exitCode !== null || w.child.signalCode !== null)) {
      return observedAt;
    }
    if (performance.now() >= deadline) {
      // Names WHICH writers, not merely how many. This branch is the one a
      // person reads on a real failure, and an index is what tells them whose
      // stderr to go and read; a bare count was the whole of it before, and it
      // discarded the per-writer structure the sweep had just built.
      const missing = observedAt
        .map((at, i) => (at === undefined ? String(i) : undefined))
        .filter((i) => i !== undefined);
      throw new Error(
        `${String(missing.length)} of ${String(readyFiles.length)} settings writers never reported ready (writers ${missing.join(', ')})`,
      );
    }
    await delay(5);
  }
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
  const writers = jobs.map((job, i) =>
    spawnWriter(base, job, readyFiles[i] ?? '', goFile, readyToken(i)),
  );
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
    releasedAt = performance.now();
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

/** What `barrierReport` says when the barrier did its job. */
export const BARRIER_HELD = 'every writer parked before the release';

/**
 * Whether every writer was parked at the barrier before ANY of them was
 * released — the barrier's own positive control — as a SENTENCE.
 *
 * The point of a barrier is contention, and one that quietly stopped working
 * would let each writer run as it finished booting, one after another. Every
 * no-loss assertion downstream then holds for want of a race, silently.
 *
 * A sentence rather than a boolean because this is what the three assertions in
 * `concurrency/settings-race.test.ts` fail on, and `expected false to be true`
 * names neither the writer nor the reason. The run holds the answer — which
 * writer was late, by how long, and how long each took to boot — and a boolean
 * throws all of it away at the last step. Compare against `BARRIER_HELD`.
 *
 * It reads the PARENT's observations against the PARENT's release, both on one
 * monotonic clock. It used to compare the child's own `readyAt` against
 * `releasedAt`: two processes stamping `Date.now()` ask two independently-
 * maintained clocks, and on Windows those disagree by a few milliseconds
 * routinely. The causal order was never in doubt — a child stamps its readiness
 * before writing the file the parent waits for — so a run that failed this
 * check was one where the clocks disagreed, not one where the barrier did. It
 * reddened main from a genuinely green tree. There is no longer an instant on
 * `WriterOutcome` to make that mistake with.
 *
 * The ready TOKEN is the evidence, not the timestamp, and it is evidence of the
 * whole property: the file carries the writer's own index, so only that child
 * could have written it, and it only exists because the child wrote it on its
 * way into the park loop. Two conjuncts, and each catches what the other
 * cannot — a writer never seen at all (the barrier released without it), and a
 * writer seen only AFTER the release (the release was reordered ahead of the
 * handshake). Both have cases; drop either conjunct and one of them reddens.
 *
 * What it deliberately does NOT assert is that the calls overlapped in wall
 * clock. A released child can be descheduled — on a runner with more test
 * processes than cores, for longer than another writer's whole call — so an
 * overlap check fails on a scheduling artifact rather than on a defect.
 * `startedAt` and `endedAt` are unreachable from here, which is what enforces
 * that; there is no case pinning it, because a case could only restate the
 * function's shape.
 */
export function barrierReport(run: ConcurrentRun): string {
  if (run.outcomes.length === 0) return 'no writers ran';
  // An arity guard on an exported predicate that takes an arbitrary
  // ConcurrentRun — NOT a claim about a shape this helper can produce. It
  // cannot: `readyObservedAt` and `outcomes` both derive from `jobs`, and
  // `sweep` writes slot `i` at most once, so a real run's lengths are always
  // equal and a double-observation would overwrite rather than lengthen.
  if (run.readyObservedAt.length !== run.outcomes.length) {
    return `run is malformed: ${String(run.readyObservedAt.length)} observations for ${String(run.outcomes.length)} writers`;
  }
  // Spread first: `every` SKIPS holes, so a sparse `readyObservedAt` would
  // never visit the missing index and a run with an unobserved writer would
  // report that the barrier held.
  const faults = [...run.readyObservedAt].flatMap((at, i) => {
    const boot = run.outcomes[i]?.bootMs;
    const took = boot === undefined ? '' : ` (booted in ${String(Math.round(boot))}ms)`;
    if (at === undefined) return [`writer ${String(i)} never parked${took}`];
    if (at > run.releasedAt) {
      return [
        `writer ${String(i)} was not observed until ${String(Math.round(at - run.releasedAt))}ms after the release${took}`,
      ];
    }
    return [];
  });
  return faults.length === 0 ? BARRIER_HELD : faults.join('; ');
}
