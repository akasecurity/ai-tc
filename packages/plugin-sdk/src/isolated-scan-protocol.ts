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

/**
 * Handed to the worker once at construction; the ruleset never changes after.
 * Both arrays are empty on a worker built only to run the timing battery —
 * `probe` jobs carry their own rule and read neither.
 */
export interface ScanWorkerData {
  // Rules with an upper bound behind them: the compiled-in packs, which CI
  // measures against the adversarial battery on every commit, plus any matcher
  // that cannot backtrack at all whatever its author wrote.
  verified: Rule[];
  // Regex rules from a pulled or custom pack, which only the runtime timing
  // battery stands behind. An attributing scan runs each of them alone first,
  // so a hang can be pinned on one of them by index.
  unverified: Rule[];
}

/** One scan request. `id` is echoed back so a late reply can be discarded. */
export interface ScanJob {
  kind: 'scan';
  id: number;
  text: string;
  filePath?: string | undefined;
  // Scan each unverified rule ALONE first, announcing its index before it
  // starts, so a hang can be pinned on one rule. OFF on the happy path: it
  // costs a whole extra pass over the unverified rules on every scanned field,
  // and only a scan that has already timed out needs the attribution.
  attribute: boolean;
}

/**
 * Measure one rule against the adversarial probe battery on the worker's
 * thread. The battery runs the rule's own pattern against inputs built to make
 * it backtrack, so it is itself an unbounded `scan()` — running it here is what
 * lets the parent kill a pattern that never returns instead of hanging on it.
 */
export interface ProbeJob {
  kind: 'probe';
  id: number;
  rule: Rule;
}

export type ScanWorkerJob = ScanJob | ProbeJob;

export type ScanWorkerMessage =
  // Posted once, as soon as the worker's module has loaded and it can accept a
  // job. Startup is charged to nobody's deadline until this arrives.
  | { kind: 'ready' }
  // The index into `unverified` of the rule about to be scanned alone, or -1
  // once the attributable stage is over. Only an attributing scan posts these.
  | { kind: 'progress'; index: number }
  | { kind: 'result'; id: number; findings: MatchResult[] }
  | { kind: 'probed'; id: number; safe: boolean; worstMs: number }
  | { kind: 'failed'; id: number; message: string };
