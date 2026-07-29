/**
 * The worker-thread side of the isolated scan. Runs the detection engine on a
 * thread of its own so the parent can kill work that never returns:
 * `worker.terminate()` reaches V8's execution terminator, which interrupts a
 * spinning regex mid-exec where nothing on the calling thread can.
 *
 * Two kinds of job cross the wire, and both are unbounded calls that a hostile
 * pattern can hang:
 *
 *   - `probe` runs the adversarial timing battery against ONE rule. The battery
 *     works by driving the rule's own pattern into backtracking, so measuring a
 *     rule is itself a way to hang on it — which is exactly why the measurement
 *     belongs on this side of the thread boundary.
 *   - `scan` runs the ruleset that arrived over `workerData` against one field.
 *
 * A `scan` job normally makes ONE `scan()` call over the whole ruleset. With
 * `attribute` set it first scans each `unverified` rule ALONE, posting the
 * rule's index before it starts, so whichever index the parent saw last names
 * the rule that was running when it pulled the plug — a terminated worker
 * cannot report anything itself, so the progress has to run ahead of the work.
 * Those per-rule findings are discarded and the combined pass is still what
 * answers: a rule with `requiresNearby` is only corroborated when its
 * neighbours are in the same `scan()`, so returning rule-by-rule results would
 * silently drop findings. The parent only asks for attribution after a scan has
 * already timed out, so the extra pass never lands on the happy path.
 *
 * Node loads this file directly on both paths: the published plugin runs the
 * bundled `scripts/scan-worker.js`, while the repo and vitest hand Node this
 * `.ts` and let it strip the types. Two constraints follow, and neither shows
 * up until the repo path runs:
 *
 *   - Plain type annotations only. No enums, no parameter properties, nothing
 *     that needs a real compile rather than an erase.
 *   - Nothing from this package beyond the protocol types. `rule-packs.ts`
 *     reaches `bundled-packs.generated.ts`, whose 101 JSON imports carry no
 *     import attributes and so fail outright under raw Node. The ruleset
 *     arrives over `workerData`, so there is nothing here to want from it.
 */
import { parentPort, workerData } from 'node:worker_threads';

import type { ScanContext } from '@akasecurity/detections';
import { checkRuleTiming, scan } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { ScanWorkerData, ScanWorkerJob, ScanWorkerMessage } from './isolated-scan-protocol.ts';

// Null only when this module is loaded on the main thread, which nothing in the
// product does. Throwing reaches the parent as a worker 'error' — the one
// channel a worker still has before it has answered anything.
if (!parentPort) throw new Error('[aka] scan-worker must be loaded on a worker thread');
const port = parentPort;

const { verified, unverified } = workerData as ScanWorkerData;
const ruleset: Rule[] = [...verified, ...unverified];

function post(message: ScanWorkerMessage): void {
  port.postMessage(message);
}

port.on('message', (job: ScanWorkerJob) => {
  try {
    if (job.kind === 'probe') {
      const { safe, worstMs } = checkRuleTiming(job.rule);
      post({ kind: 'probed', id: job.id, safe, worstMs });
      return;
    }
    const context: ScanContext | undefined =
      job.filePath === undefined ? undefined : { filePath: job.filePath };
    if (job.attribute) {
      for (const [index, rule] of unverified.entries()) {
        post({ kind: 'progress', index });
        scan(job.text, [rule], context);
      }
      // -1 = past the attributable stage. A hang from here on is in the
      // combined pass, which the parent must NOT pin on any single rule.
      post({ kind: 'progress', index: -1 });
    }
    post({ kind: 'result', id: job.id, findings: scan(job.text, ruleset, context) });
  } catch (error) {
    post({
      kind: 'failed',
      id: job.id,
      message: error instanceof Error ? error.message : 'the job failed',
    });
  }
});

// Last, so the parent starts its deadline only once this thread can actually
// take a job. Charging module load to the first job's budget would make a cold
// or contended machine — a Windows runner scanning a freshly written script,
// say — look like a rule that hung.
post({ kind: 'ready' });
