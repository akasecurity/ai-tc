import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import type { MatchResult, ScanContext } from '@akasecurity/detections';

import type { ScanJob, ScanWorkerData, ScanWorkerMessage } from './isolated-scan-protocol.ts';

/**
 * The parent side of the isolated scan: a pooled worker thread plus a wall-clock
 * deadline, so a rule that never returns is killed instead of eating the hook's
 * whole budget.
 *
 * The timing pre-flight (`rule-quarantine.ts`) measures a rule against a fixed
 * adversarial battery and is empirical — a pattern crafted against that battery
 * can pass it and still backtrack forever on real text. This is the hard bound
 * underneath it: `worker.terminate()` reaches V8's execution terminator, which
 * interrupts a running regex. Nothing on the calling thread can, which is why
 * `scan()` alone has no upper bound at all.
 *
 * No `SharedArrayBuffer` and no `Atomics.wait`. Every caller of `scan()` on the
 * capture path is already async (`runtime.evaluate`), so the deadline can be an
 * ordinary timer and the parent's event loop stays live while the worker runs.
 * That is what makes the failure paths reportable: a worker that dies before it
 * answers delivers an `'error'` event, so a crash is reported as a crash. A
 * parent parked in `Atomics.wait` could not receive that event — its handler
 * would be queued behind a loop that is not running — and would report the
 * crash as a timeout after waiting out the entire budget.
 *
 * What it costs, measured on an arm64 Mac against the 101 bundled rules plus
 * one pulled rule, and paid ONLY on a machine that has such a rule at all (see
 * `guarded-scan.ts` — otherwise no worker is started):
 *
 *   - Worker start + first scan: ~15 ms from the bundled `scan-worker.js`,
 *     ~48 ms in the repo where Node strips the types first. Once per process.
 *   - A 2 KB prompt: 0.24 ms p50 / 0.36 ms p99 through the worker, against
 *     0.17 ms in-process — roughly 0.07 ms of message round trip per field.
 *   - A 1 MB field (the per-leaf cap): 33 ms against 27 ms in-process; the
 *     extra is the structured clone of the text, not the scan.
 */

// The hard bound on one isolated scan, worker startup included. Sized against
// the hook's 10s harness timeout, not against a typical scan: a 1MB field (the
// per-leaf cap) targets ~500ms across the full ruleset, so this leaves ~4x
// headroom for a slow machine while still leaving the hook most of its budget
// to recover, warn and persist a quarantine after a hang.
export const ISOLATED_SCAN_BUDGET_MS = 2_000;

// How long the rule that was running at the deadline must have been running
// before the hang is pinned on it. A rule the worker had only just started is
// not evidence of anything — the budget may simply have run out around it —
// and the verdict this feeds is persistent, so it errs toward naming nobody.
const ATTRIBUTION_MIN_RULE_MS = 500;

export type IsolatedScanOutcome =
  | { status: 'ok'; findings: MatchResult[] }
  // The deadline fired and the worker was terminated. `culpritIndex` indexes
  // `ScanWorkerData.unverified`, and is undefined when the hang could not be
  // pinned on one rule (it happened in the combined pass, or too early to tell).
  | { status: 'timeout'; culpritIndex: number | undefined; elapsedMs: number }
  // No verdict: the worker could not be started, died, or the scan threw inside
  // it. Callers must NOT read this as "nothing was found".
  | { status: 'unavailable'; reason: string };

export interface IsolatedScanner {
  scan(text: string, context?: ScanContext): Promise<IsolatedScanOutcome>;
  close(): Promise<void>;
}

export interface IsolatedScanOptions {
  budgetMs?: number | undefined;
  minAttributionMs?: number | undefined;
  // Overridden by tests to point at a worker that misbehaves on purpose.
  workerUrl?: URL | undefined;
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
  startedAt: number;
  // The last index the worker announced, and when it announced it. -1 means
  // "not inside the attributable stage" — before the first rule, or past the
  // last one.
  progressIndex: number;
  progressAt: number;
  timer: ReturnType<typeof setTimeout>;
  resolve(outcome: IsolatedScanOutcome): void;
}

/**
 * One worker, reused for every scan in this process. Startup (thread + the
 * engine's own copy of the ruleset) is paid once, not per field — a single
 * PreToolUse hook can scan up to `MCP_MAX_LEAF_COUNT` fields, and a worker per
 * field would be the dominant cost of the whole hook.
 */
export function createIsolatedScanner(
  data: ScanWorkerData,
  opts: IsolatedScanOptions = {},
): IsolatedScanner {
  const budgetMs = opts.budgetMs ?? ISOLATED_SCAN_BUDGET_MS;
  const minAttributionMs = opts.minAttributionMs ?? ATTRIBUTION_MIN_RULE_MS;

  let worker: Worker | undefined;
  // Latched once the thread errors or exits on its own. A worker we terminated
  // on a deadline does not latch it — that one is replaceable.
  let broken: string | undefined;
  let closed = false;
  let nextJobId = 1;
  let pending: PendingJob | undefined;
  // Scans run one at a time. The capture path is already sequential, but the
  // worker holds one job slot, so the chain is what makes that a property of
  // this module rather than an assumption about its callers.
  let chain: Promise<void> = Promise.resolve();

  function settle(outcome: IsolatedScanOutcome): void {
    const job = pending;
    if (!job) return;
    pending = undefined;
    clearTimeout(job.timer);
    // Idle again: the thread must not be what keeps the process alive.
    worker?.unref();
    job.resolve(outcome);
  }

  function discard(dead: Worker): void {
    if (worker === dead) worker = undefined;
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
    started.on('message', (message: ScanWorkerMessage) => {
      if (message.kind === 'progress') {
        if (pending) {
          pending.progressIndex = message.index;
          pending.progressAt = performance.now();
        }
        return;
      }
      // A reply whose id does not match arrived for a job already abandoned on
      // a deadline; the outcome for that job is already decided.
      if (pending?.id !== message.id) return;
      if (message.kind === 'result') settle({ status: 'ok', findings: message.findings });
      else settle({ status: 'unavailable', reason: `the scan worker failed: ${message.message}` });
    });
    started.on('error', (error) => {
      broken = messageOf(error);
      discard(started);
      settle({ status: 'unavailable', reason: `the scan worker crashed: ${broken}` });
    });
    started.on('exit', () => {
      discard(started);
      settle({ status: 'unavailable', reason: 'the scan worker exited before answering' });
    });
    started.unref();
    worker = started;
    return started;
  }

  function runOne(text: string, context: ScanContext | undefined): Promise<IsolatedScanOutcome> {
    return new Promise<IsolatedScanOutcome>((resolve) => {
      if (closed) {
        resolve({ status: 'unavailable', reason: 'the scan worker is closed' });
        return;
      }
      if (broken !== undefined) {
        // A thread that died on its own dies the same way again; respawning it
        // would spend a fresh budget to learn nothing.
        resolve({ status: 'unavailable', reason: `the scan worker crashed: ${broken}` });
        return;
      }
      const started = ensureWorker();
      if (!(started instanceof Worker)) {
        broken = started.error;
        resolve({ status: 'unavailable', reason: started.error });
        return;
      }

      const id = nextJobId++;
      const startedAt = performance.now();
      const timer = setTimeout(() => {
        const job = pending;
        if (!job) return;
        // The worker cannot report which rule hung — it is about to be killed
        // mid-instruction — so the answer is whichever rule it announced last,
        // and only when it has been on that rule long enough to be the cause.
        const runningMs = performance.now() - job.progressAt;
        const culpritIndex =
          job.progressIndex >= 0 && runningMs >= minAttributionMs ? job.progressIndex : undefined;
        discard(started);
        // terminate() is what makes the bound hard: it reaches V8's execution
        // terminator and interrupts a spinning regex mid-exec.
        void started.terminate();
        settle({ status: 'timeout', culpritIndex, elapsedMs: performance.now() - startedAt });
      }, budgetMs);

      pending = { id, startedAt, progressIndex: -1, progressAt: startedAt, timer, resolve };
      started.ref();
      const job: ScanJob = { id, text, filePath: context?.filePath };
      try {
        started.postMessage(job);
      } catch (error) {
        // The thread went away between the ref and the post.
        settle({
          status: 'unavailable',
          reason: `could not reach the scan worker: ${messageOf(error)}`,
        });
      }
    });
  }

  return {
    scan(text, context) {
      const next = chain.then(() => runOne(text, context));
      // Swallow on the CHAIN only, never on `next`: a rejection that stayed in
      // the chain would skip every queued scan after it, turning one unexpected
      // throw into a scanner that answers nothing for the rest of the process.
      chain = next.then(
        () => undefined,
        () => undefined,
      );
      return next;
    },
    async close() {
      closed = true;
      const live = worker;
      worker = undefined;
      settle({ status: 'unavailable', reason: 'the scan worker is closed' });
      if (live) await live.terminate();
    },
  };
}
