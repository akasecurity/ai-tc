/**
 * Counts the worker threads an isolated scanner builds.
 *
 * How many threads a path starts is what the isolation cases are really
 * asserting — two to recover from a hang and then name the rule that caused it,
 * one for the timing pre-flight, none at all when nothing needs bounding. The
 * only other instrument for it is elapsed milliseconds, and a ceiling loose
 * enough to survive a cold start on a contended runner is loose enough to
 * swallow a whole extra cycle: a count is the same shape check, stated
 * directly, and runner-independent.
 *
 * `count()` is DISTINCT ids, not notifications. A thread id is unique within
 * the process and is never reused, so a seam that announced one construction
 * twice cannot inflate the count, while a genuinely extra thread always can.
 * `ids()` keeps the raw log so a count that comes out wrong can say which
 * threads it saw rather than only how many.
 *
 * A peer COPY of the plugin SDK's counter, not an import: that one lives under
 * `packages/plugin-sdk/test/`, which no package wall lets `local-ops` reach. The
 * copy brings `worker-starts.test.ts` with it for the reason that suite states —
 * weakening the counter fails none of its callers, so the only thing that can
 * catch it is a suite pointed at the counter itself.
 */
export interface WorkerStarts {
  /** Hand to `GuardedFileScannerOptions.onWorkerStart`. */
  onWorkerStart: (threadId: number) => void;
  /** Distinct threads started so far. */
  count: () => number;
  /** Every id reported, in arrival order, duplicates included. */
  ids: () => number[];
}

export function countWorkerStarts(): WorkerStarts {
  const reported: number[] = [];
  return {
    onWorkerStart: (threadId) => {
      reported.push(threadId);
    },
    count: () => new Set(reported).size,
    ids: () => [...reported],
  };
}
