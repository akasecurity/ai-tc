import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import type { MatchResult, ScanContext } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type {
  ProbeJob,
  ScanJob,
  ScanWorkerData,
  ScanWorkerMessage,
} from './isolated-scan-protocol.ts';

/**
 * The parent side of the isolated scan: a pooled worker thread plus a wall-clock
 * deadline, so work that never returns is killed instead of eating the hook's
 * whole budget.
 *
 * Two things run out here, and both are unbounded calls on an untrusted pattern:
 *
 *   - `probe` — the timing battery for ONE rule. The battery decides whether a
 *     pulled rule is safe by driving its pattern into backtracking, so running
 *     it is itself a way to hang on the rule. Measuring in-process would leave
 *     the pre-flight as the unbounded call the scan bound exists to remove.
 *   - `scan` — the ruleset against one field.
 *
 * `worker.terminate()` reaches V8's execution terminator, which interrupts a
 * running regex. Nothing on the calling thread can, which is why either call
 * alone has no upper bound at all.
 *
 * No `SharedArrayBuffer` and no `Atomics.wait`. Every caller on the capture path
 * is already async (`runtime.evaluate`), so the deadline can be an ordinary
 * timer and the parent's event loop stays live while the worker runs. That is
 * what makes the failure paths reportable: a worker that dies before it answers
 * delivers an `'error'` event, so a crash is reported as a crash. A parent
 * parked in `Atomics.wait` could not receive that event — its handler would be
 * queued behind a loop that is not running — and would report the crash as a
 * timeout after waiting out the entire budget.
 *
 * What it costs, measured on an arm64 Mac against the 101 bundled rules plus a
 * pulled pack, and paid ONLY on a machine that has a pulled/custom regex rule at
 * all (see `guarded-scan.ts` — otherwise no worker is started):
 *
 *   - Worker start: 14.5 ms from the bundled `scan-worker.js`, 39 ms in the repo
 *     where Node strips the types first. Once per process, and charged to no
 *     deadline — the worker announces itself with `ready` first.
 *   - A 2 KB prompt: 0.193 ms p50 / 0.379 ms p99 through the worker, against
 *     0.173 ms in-process — about 0.02 ms of message round trip per field.
 *   - A 1 MB field (the per-leaf cap): 26.3 ms against 26.0 ms in-process; the
 *     structured clone of the text is ~0.3 ms, not a multiple of the scan.
 *   - Scaling in the pulled ruleset is the SAME as in-process, because an
 *     ordinary scan makes ONE `scan()` call over the whole ruleset. Measured on
 *     a 2 KB field at 1 / 50 / 200 pulled rules, the isolated:in-process ratio
 *     is 1.10 / 1.12 / 1.10 — flat. Keep it that way: the attribution pass walks
 *     the unverified rules one at a time, and it belongs to the retry of a scan
 *     that already timed out, never to a scan that works.
 *   - The pre-flight, when a rule's verdict is not cached: 12.3 ms for the first
 *     rule (nearly all of it the worker start) and 0.31 ms/rule amortized over
 *     50. It runs once per rule ever, and a machine whose verdicts are all
 *     cached — the steady state — starts no worker for it at all.
 */

// The hard bound on one isolated scan. Sized against the hook's 10s harness
// timeout, not against a typical scan: a 1MB field (the per-leaf cap) targets
// ~500ms across the full ruleset, so this leaves ~4x headroom for a slow machine
// while still leaving the hook most of its budget to recover, warn and persist a
// quarantine after a hang.
export const ISOLATED_SCAN_BUDGET_MS = 2_000;

// The hard bound on measuring ONE rule against the timing battery. The battery's
// own per-probe budget is 100ms and it stops at the first probe that blows it,
// so a rule that returns at all is done in well under a second — the 90 bundled
// regex rules measure 0.2ms mean and 2.1ms worst for a whole battery on an arm64
// Mac, ~100x under this even at the Windows runner's 4-5x backtracking penalty.
// Only a pattern that never returns reaches this deadline.
export const ISOLATED_PROBE_BUDGET_MS = 1_000;

// How long the worker has to load its module and announce itself. Charged
// separately from a job's budget so a cold or contended machine — a Windows
// runner whose antivirus is reading a freshly written script, say — is reported
// as a slow start rather than misread as a rule that hung.
export const ISOLATED_START_BUDGET_MS = 5_000;

// How long the rule that was running at the deadline must have been running
// before the hang is pinned on it. A rule the worker had only just started is
// not evidence of anything — the budget may simply have run out around it —
// and the verdict this feeds is persistent, so it errs toward naming nobody.
const ATTRIBUTION_MIN_RULE_MS = 500;

// …and how much of the whole job that rule must account for. A fixed floor
// alone answers "was it running long enough to matter", never "was it the
// reason" — a machine that freezes mid-rule clears any floor you pick, and the
// verdict this feeds is persistent and never re-measured. A rule that genuinely
// cannot return is entered early and holds the thread until it is killed, so
// its residency approaches the whole elapsed job; a rule that was merely
// resident when a stall hit does not. The ratio is scale-free — it needs no
// retuning when the budget moves — which is the same reasoning
// `CATASTROPHIC_RATIO` uses in the probe battery.
const ATTRIBUTION_MIN_SHARE = 0.5;

/** The two ways a job ends without an answer. Shared by both job kinds. */
export type IsolatedFailure =
  // The deadline fired and the worker was terminated. `culpritIndex` indexes
  // `ScanWorkerData.unverified`, and is set only on an attributing scan that
  // was inside a single rule long enough to blame it. A probe never sets it:
  // the rule under measurement is the culprit and the caller already knows it.
  | { status: 'timeout'; culpritIndex: number | undefined; elapsedMs: number }
  // No verdict: the worker could not be started, died, or the job threw inside
  // it. Callers must NOT read this as "nothing was found".
  | { status: 'unavailable'; reason: string };

export type IsolatedScanOutcome = { status: 'ok'; findings: MatchResult[] } | IsolatedFailure;

export type IsolatedProbeOutcome =
  { status: 'ok'; safe: boolean; worstMs: number } | IsolatedFailure;

export interface IsolatedScanOptions {
  budgetMs?: number | undefined;
  probeBudgetMs?: number | undefined;
  startBudgetMs?: number | undefined;
  minAttributionMs?: number | undefined;
  // Overridden by tests to point at a worker that misbehaves on purpose.
  workerUrl?: URL | undefined;
}

export interface IsolatedScanner {
  /**
   * Scan one field under the deadline. `attribute` makes the worker walk the
   * unverified rules one at a time first so a hang can be named; it costs a
   * whole extra pass, so only a retry of a scan that already timed out asks
   * for it.
   */
  scan(
    text: string,
    context?: ScanContext,
    opts?: { attribute?: boolean },
  ): Promise<IsolatedScanOutcome>;
  /** Measure one rule against the adversarial timing battery, under the deadline. */
  probe(rule: Rule): Promise<IsolatedProbeOutcome>;
  close(): Promise<void>;
}

// Resolved lazily and once: a process that never isolates a scan never pays for
// the probe, and one that does pays twice at most.
let resolvedWorkerUrl: URL | null | undefined;

/**
 * Where the worker script lives, on both shapes this code ships in.
 *
 * The published plugin bundles each hook into a self-contained `scripts/*.js`
 * on a machine with no `node_modules`, and the worker is one more script beside
 * them — so `./scan-worker.js` resolves against the emitting hook. In the repo
 * (and under vitest) this module is still `src/isolated-scan.ts` and its
 * neighbour is `scan-worker.ts`, which Node loads by stripping the types.
 *
 * `.js` is tried first so a published bundle can never be shadowed by a stray
 * source file. `undefined` — neither present, or a location that is not a file
 * path at all — is a real answer: the caller falls back rather than scanning
 * unbounded.
 */
function resolveWorkerUrl(): URL | undefined {
  if (resolvedWorkerUrl !== undefined) return resolvedWorkerUrl ?? undefined;
  for (const name of ['scan-worker.js', 'scan-worker.ts']) {
    const candidate = new URL(name, import.meta.url);
    try {
      if (existsSync(fileURLToPath(candidate))) {
        resolvedWorkerUrl = candidate;
        return candidate;
      }
    } catch {
      // Not a file: URL — a single-file executable, say. Nothing to probe.
    }
  }
  resolvedWorkerUrl = null;
  return undefined;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface PendingJob {
  id: number;
  // The worker this job was posted to. Every worker event is checked against
  // it, so a thread we already terminated cannot settle a job that belongs to
  // its replacement.
  worker: Worker;
  budgetMs: number;
  startedAt: number;
  // The last index the worker announced, and when it announced it. -1 means
  // "not inside the attributable stage" — before the first rule, past the last
  // one, or a job that never attributes at all.
  progressIndex: number;
  progressAt: number;
  // Runs until the worker says it can take a job; replaced by `timer` on ready.
  startupTimer: ReturnType<typeof setTimeout> | undefined;
  timer: ReturnType<typeof setTimeout> | undefined;
  /** Hands a matching reply to the caller. False when the reply is for another job kind. */
  reply: (message: ScanWorkerMessage) => boolean;
  /** Ends the job without an answer. */
  fail: (outcome: IsolatedFailure) => void;
}

/**
 * One worker, reused for every job in this process. Startup (thread + the
 * engine's own copy of the ruleset) is paid once, not per field — a single
 * PreToolUse hook can scan up to `MCP_MAX_LEAF_COUNT` fields, and a worker per
 * field would be the dominant cost of the whole hook.
 */
export function createIsolatedScanner(
  data: ScanWorkerData,
  opts: IsolatedScanOptions = {},
): IsolatedScanner {
  const budgetMs = opts.budgetMs ?? ISOLATED_SCAN_BUDGET_MS;
  const probeBudgetMs = opts.probeBudgetMs ?? ISOLATED_PROBE_BUDGET_MS;
  const startBudgetMs = opts.startBudgetMs ?? ISOLATED_START_BUDGET_MS;
  const minAttributionMs = opts.minAttributionMs ?? ATTRIBUTION_MIN_RULE_MS;

  let worker: Worker | undefined;
  // The worker that has posted `ready`. Compared by identity, so a replacement
  // thread starts unready however many workers came before it.
  let readyWorker: Worker | undefined;
  // Latched once the thread errors or exits on its own. A worker we terminated
  // on a deadline does not latch it — that one is replaceable.
  let broken: string | undefined;
  let closed = false;
  let nextJobId = 1;
  let pending: PendingJob | undefined;
  // Terminations in flight. close() awaits them, so "closed" means the threads
  // are actually gone rather than merely asked to go.
  const terminating = new Set<Promise<unknown>>();
  // Jobs run one at a time. The capture path is already sequential, but the
  // worker holds one job slot, so the chain is what makes that a property of
  // this module rather than an assumption about its callers.
  let chain: Promise<void> = Promise.resolve();

  function clearTimers(job: PendingJob): void {
    if (job.startupTimer !== undefined) clearTimeout(job.startupTimer);
    if (job.timer !== undefined) clearTimeout(job.timer);
  }

  /** Detaches the pending job so exactly one path can end it. */
  function take(): PendingJob | undefined {
    const job = pending;
    if (!job) return undefined;
    pending = undefined;
    clearTimers(job);
    // Idle again: the thread must not be what keeps the process alive.
    worker?.unref();
    return job;
  }

  function failPending(outcome: IsolatedFailure): void {
    take()?.fail(outcome);
  }

  function kill(dead: Worker): void {
    if (worker === dead) worker = undefined;
    if (readyWorker === dead) readyWorker = undefined;
    // terminate() is what makes the bound hard: it reaches V8's execution
    // terminator and interrupts a spinning regex mid-exec.
    const done = dead.terminate().catch(() => undefined);
    terminating.add(done);
    void done.finally(() => terminating.delete(done));
  }

  function onDeadline(job: PendingJob): void {
    if (pending !== job) return;
    // The worker cannot report which rule hung — it is about to be killed
    // mid-instruction — so the answer is whichever rule it announced last, and
    // only when the evidence says that rule is the CAUSE rather than merely
    // what happened to be running. Both tests have to pass: it ran long enough
    // to matter at all, and it accounts for most of the job. Naming nobody
    // costs one re-measurement next process; naming the wrong rule disables a
    // legitimate detection until someone runs `aka detections unquarantine`.
    const now = performance.now();
    const runningMs = now - job.progressAt;
    const elapsedMs = now - job.startedAt;
    const blamed =
      job.progressIndex >= 0 &&
      runningMs >= minAttributionMs &&
      runningMs >= elapsedMs * ATTRIBUTION_MIN_SHARE;
    const culpritIndex = blamed ? job.progressIndex : undefined;
    kill(job.worker);
    failPending({ status: 'timeout', culpritIndex, elapsedMs });
  }

  function ensureWorker(): Worker | { error: string } {
    if (worker) return worker;
    const url = opts.workerUrl ?? resolveWorkerUrl();
    if (!url) {
      return {
        error: 'the scan worker script was not found next to this bundle',
      };
    }
    let started: Worker;
    try {
      started = new Worker(url, { workerData: data });
    } catch (error) {
      return { error: `could not start the scan worker: ${messageOf(error)}` };
    }
    // Every handler below is scoped to the worker it was installed for. A
    // thread we terminated on a deadline delivers its 'exit' AFTER the parent
    // has already started a replacement, so an unscoped handler would settle
    // the replacement's job with the dead thread's verdict.
    started.on('message', (message: ScanWorkerMessage) => {
      if (worker !== started) return;
      if (message.kind === 'ready') {
        readyWorker = started;
        if (pending?.worker === started) beginDeadline(pending);
        return;
      }
      if (message.kind === 'progress') {
        if (pending?.worker === started) {
          pending.progressIndex = message.index;
          pending.progressAt = performance.now();
        }
        return;
      }
      // A reply whose id does not match arrived for a job already abandoned on
      // a deadline; the outcome for that job is already decided.
      if (pending?.id !== message.id) return;
      if (message.kind === 'failed') {
        failPending({
          status: 'unavailable',
          reason: `the scan worker failed: ${message.message}`,
        });
        return;
      }
      const job = take();
      // The worker answered the wrong kind of job. Impossible while the id
      // matches, so treat it as the worker being unusable rather than guessing.
      if (job && !job.reply(message)) {
        job.fail({ status: 'unavailable', reason: 'the scan worker answered the wrong job' });
      }
    });
    started.on('error', (error) => {
      if (worker !== started) return;
      broken = messageOf(error);
      worker = undefined;
      if (readyWorker === started) readyWorker = undefined;
      failPending({ status: 'unavailable', reason: `the scan worker crashed: ${broken}` });
    });
    started.on('exit', () => {
      if (worker !== started) return;
      // Reaching here past the identity guard means the thread went on its own:
      // both `kill()` and `close()` clear `worker` before terminating, so a
      // parent-initiated exit returns above. A thread that dies by itself dies
      // the same way again, so latch it — otherwise `filterUnsafeRules` keeps
      // iterating (it warns and continues on `unavailable`) and spends the
      // whole pass budget constructing threads that immediately exit.
      // `??=` leaves a real 'error' message in place; 'error' is emitted first.
      broken ??= 'the scan worker exited before answering';
      worker = undefined;
      if (readyWorker === started) readyWorker = undefined;
      failPending({ status: 'unavailable', reason: 'the scan worker exited before answering' });
    });
    started.unref();
    worker = started;
    return started;
  }

  /** Swaps the startup grace period for the job's own deadline. */
  function beginDeadline(job: PendingJob): void {
    if (job.startupTimer !== undefined) {
      clearTimeout(job.startupTimer);
      job.startupTimer = undefined;
    }
    if (job.timer !== undefined) return;
    job.startedAt = performance.now();
    job.progressAt = job.startedAt;
    job.timer = setTimeout(() => {
      onDeadline(job);
    }, job.budgetMs);
  }

  interface JobSpec {
    budgetMs: number;
    build: (id: number) => ScanJob | ProbeJob;
    reply: (message: ScanWorkerMessage) => boolean;
  }

  function runOne(spec: JobSpec, fail: (outcome: IsolatedFailure) => void): void {
    if (closed) {
      fail({ status: 'unavailable', reason: 'the scan worker is closed' });
      return;
    }
    if (broken !== undefined) {
      // A thread that died on its own dies the same way again; respawning it
      // would spend a fresh budget to learn nothing.
      fail({ status: 'unavailable', reason: `the scan worker crashed: ${broken}` });
      return;
    }
    const started = ensureWorker();
    if (!(started instanceof Worker)) {
      broken = started.error;
      fail({ status: 'unavailable', reason: started.error });
      return;
    }

    const id = nextJobId++;
    const now = performance.now();
    const job: PendingJob = {
      id,
      worker: started,
      budgetMs: spec.budgetMs,
      startedAt: now,
      progressIndex: -1,
      progressAt: now,
      startupTimer: undefined,
      timer: undefined,
      reply: spec.reply,
      fail,
    };
    pending = job;
    started.ref();

    if (readyWorker === started) {
      beginDeadline(job);
    } else {
      // A worker that never finishes loading must not hang here either.
      job.startupTimer = setTimeout(() => {
        if (pending !== job) return;
        kill(job.worker);
        failPending({
          status: 'unavailable',
          reason: `the scan worker did not start within ${String(startBudgetMs)}ms`,
        });
      }, startBudgetMs);
    }

    try {
      started.postMessage(spec.build(id));
    } catch (error) {
      failPending({
        // The thread went away between the ref and the post.
        status: 'unavailable',
        reason: `could not reach the scan worker: ${messageOf(error)}`,
      });
    }
  }

  /** Queues `spec` behind whatever is already running. */
  function enqueue<T>(spec: (resolve: (outcome: T) => void) => void): Promise<T> {
    const next = chain.then(
      () =>
        new Promise<T>((resolve) => {
          spec(resolve);
        }),
    );
    // Swallow on the CHAIN only, never on `next`: a rejection that stayed in
    // the chain would skip every queued job after it, turning one unexpected
    // throw into a scanner that answers nothing for the rest of the process.
    chain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  return {
    scan(text, context, scanOpts) {
      return enqueue<IsolatedScanOutcome>((resolve) => {
        runOne(
          {
            budgetMs,
            build: (id) => ({
              kind: 'scan',
              id,
              text,
              filePath: context?.filePath,
              attribute: scanOpts?.attribute === true,
            }),
            reply: (message) => {
              if (message.kind !== 'result') return false;
              resolve({ status: 'ok', findings: message.findings });
              return true;
            },
          },
          resolve,
        );
      });
    },
    probe(rule) {
      return enqueue<IsolatedProbeOutcome>((resolve) => {
        runOne(
          {
            budgetMs: probeBudgetMs,
            build: (id) => ({ kind: 'probe', id, rule }),
            reply: (message) => {
              if (message.kind !== 'probed') return false;
              resolve({ status: 'ok', safe: message.safe, worstMs: message.worstMs });
              return true;
            },
          },
          resolve,
        );
      });
    },
    async close() {
      closed = true;
      const live = worker;
      worker = undefined;
      readyWorker = undefined;
      failPending({ status: 'unavailable', reason: 'the scan worker is closed' });
      if (live) kill(live);
      // Every thread this scanner started is gone before close() resolves —
      // "closed" must not mean "asked to close".
      await Promise.all([...terminating]);
    },
  };
}
