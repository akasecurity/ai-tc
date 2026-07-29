import type { MatchResult } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

/**
 * The wire between the isolated scan's two sides. It lives in a file of its own
 * so `scan-worker.ts` never imports the parent-side pool: the worker is loaded
 * on its own thread and, in the published plugin, bundled as a separate script,
 * so an accidental value import would drag `node:worker_threads`'s `Worker` and
 * the whole pool into it.
 *
 * Everything here crosses a structured clone, so it stays plain data.
 */

/** Handed to the worker once at construction; the ruleset never changes after. */
export interface ScanWorkerData {
  // Rules with an upper bound behind them: the compiled-in packs, which CI
  // measures against the adversarial battery on every commit, plus any matcher
  // that cannot backtrack at all whatever its author wrote.
  verified: Rule[];
  // Regex rules from a pulled or custom pack, which only the runtime timing
  // battery stands behind. Scanned alone first so a hang can be pinned on one
  // of them by index.
  unverified: Rule[];
}

/** One scan request. `id` is echoed back so a late reply can be discarded. */
export interface ScanJob {
  id: number;
  text: string;
  filePath?: string | undefined;
}

export type ScanWorkerMessage =
  // The index into `unverified` of the rule about to be scanned alone, or -1
  // once the attributable stage is over.
  | { kind: 'progress'; index: number }
  | { kind: 'result'; id: number; findings: MatchResult[] }
  | { kind: 'failed'; id: number; message: string };
