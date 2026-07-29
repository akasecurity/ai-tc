/**
 * The worker-thread side of the isolated scan. Runs `scan()` on a thread of its
 * own so the parent can kill a rule that never returns: `worker.terminate()`
 * reaches V8's execution terminator, which interrupts a spinning regex mid-exec
 * where nothing on the calling thread can.
 *
 * The ruleset arrives once via `workerData` and is reused for every job, so a
 * scan costs one message each way rather than a fresh clone of the rules.
 *
 * A job runs in two stages, and the split is what makes a hang attributable:
 *
 *   1. Each `unverified` rule is scanned ALONE, with the rule's index posted
 *      before it starts. Whichever index the parent saw last is the rule that
 *      was running when it pulled the plug — a terminated worker cannot report
 *      anything itself, so the progress has to run ahead of the work.
 *   2. The whole ruleset is scanned in one call, and those findings are the
 *      result. Stage 1's are discarded: a rule with `requiresNearby` is only
 *      corroborated when its neighbours are in the same `scan()`, so returning
 *      rule-by-rule results would silently drop findings.
 *
 * Stage 1 costs one extra pass over the unverified rules — a pulled or custom
 * pack, never the bundled ~100 — and buys exact attribution without a second
 * worker or a second timeout budget.
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
import { scan } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { ScanJob, ScanWorkerData, ScanWorkerMessage } from './isolated-scan-protocol.ts';

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

port.on('message', (job: ScanJob) => {
  const context: ScanContext | undefined =
    job.filePath === undefined ? undefined : { filePath: job.filePath };
  try {
    for (const [index, rule] of unverified.entries()) {
      post({ kind: 'progress', index });
      scan(job.text, [rule], context);
    }
    // -1 = past the attributable stage. A hang from here on is in the combined
    // pass, which the parent must NOT pin on any single rule.
    post({ kind: 'progress', index: -1 });
    post({ kind: 'result', id: job.id, findings: scan(job.text, ruleset, context) });
  } catch (error) {
    post({
      kind: 'failed',
      id: job.id,
      message: error instanceof Error ? error.message : 'scan failed',
    });
  }
});
