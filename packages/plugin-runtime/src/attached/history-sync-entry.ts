import { dataDir, defaultDataDir, settingsDir } from '@akasecurity/persistence';

import type { HistorySyncOutcome } from './history-state.ts';
import { readHistorySyncState, writeHistorySyncState } from './history-state.ts';
import type { HistorySyncSkipReason } from './history-sync.ts';
import { runHistorySync } from './history-sync.ts';

/**
 * What one pass did — the outcome if it ran, the reason if it did not.
 *
 * Two enums in one union rather than a shared vocabulary: an OUTCOME is
 * something a deployment did and a SKIP REASON is something this machine
 * decided, and collapsing them would let a surface report a plane that was
 * never called. Both are closed sets and neither is derived from a response.
 */
export type HistorySyncPassReport = HistorySyncOutcome | HistorySyncSkipReason;

/**
 * The pass's injectable seams, for tests only.
 *
 * Everything here has a real default and production passes none of it. It exists
 * because the state this entry writes is only observable ACROSS passes, and a
 * second pass that has work climbs the retry ladder with real timers — several
 * seconds of sleeps against a 20s testTimeout, on top of the store opens, which
 * on the Windows leg is tighter than it looks. Handing the pass its clock and a
 * sender makes that deterministic instead of merely usually-fast.
 */
export type HistorySyncPassSeams = Pick<
  Parameters<typeof runHistorySync>[0],
  'now' | 'sleep' | 'random' | 'sendBatch' | 'sendCaptures'
>;

/**
 * The detached child's whole program for the history drain.
 *
 * Each harness ships a short entry that imports this and calls it, so the drain
 * is written once here rather than three times in three plugin trees.
 * `triggerHistorySync` is what spawns those entries.
 *
 * NEVER THROWS, and never signals through its exit code. It runs with stdio
 * ignored and no parent watching, so a rejection would be an unhandled
 * rejection whose only effect is a status nobody reads. What a failure produces
 * instead is a recorded outcome, which is what `aka status` renders.
 *
 * A SKIP REASON rather than an outcome means NO PASS WAS MADE — not attached, no
 * grant, the breaker is open, or another drain holds the claim — and nothing is
 * written down for it. That is distinct from every recorded outcome, each of
 * which describes something a deployment did, and writing one would re-create a
 * file a detach just removed.
 *
 * The reason is RETURNED rather than discarded here, which is the whole of this
 * change: it used to be flattened to `null` at this boundary, so `aka
 * sync-history --run` could say only that nothing happened, never which of the
 * seven ways of doing nothing it was.
 */
export async function runHistorySyncPass(
  base: string = defaultDataDir(),
  seams: HistorySyncPassSeams = {},
): Promise<HistorySyncPassReport> {
  try {
    const dir = dataDir(base);
    const result = await runHistorySync({
      base,
      settingsDir: settingsDir(base),
      dataDir: dir,
      ...seams,
    });
    // Unchanged in EFFECT: a pass that made no attempt still writes nothing.
    // Recording an outcome for it would have status report a deployment this
    // machine never called, and would re-create a file a detach just removed —
    // the reason the old `null` existed. What changes is that the reason now
    // reaches the caller instead of being discarded here.
    if (!result.attempted) return result.reason;

    const previous = readHistorySyncState(dir);
    // BOTH lanes. `counts` is structural-only by construction, so on its own it
    // would report the drain finished — and pin completedAtMs for the life of
    // the install — while the capture lane still owed thousands of rows.
    const done = result.counts.pending === 0 && !result.capturesPending;
    writeHistorySyncState(dir, {
      phase: done ? 'complete' : 'filling',
      lastOutcome: result.outcome,
      lastPassAtMs: result.atMs,
      sentTotal: result.counts.sent,
      pendingTotal: result.counts.pending,
      // BOTH lanes, and BOTH lifetime. `counts.skipped` filters to structural
      // rows, so a capture rebuildCapture refused — stamped -1 and dropped for
      // ever — was counted on no surface at all. Silence is the right shape for a
      // TRANSIENT failure everywhere else in this repo; this one is terminal, so
      // it owes a number.
      //
      // Both terms are ledger totals rather than this pass's tally, which is the
      // part that matters: a per-pass delta added to a lifetime total gives a
      // field whose capture half is one pass wide, so the surface beside
      // `sentTotal` and `pendingTotal` would announce a permanent loss once and
      // drop it on the next pass, while the rows stayed gone.
      skippedTotal: result.counts.skipped + result.counts.capturesSkipped,
      // The first pass that ran is when this machine started sending, and it
      // keeps that answer across every later pass.
      startedAtMs: previous?.startedAtMs ?? result.atMs,
      // Stamped the first time BOTH lanes were empty. The structural backlog is
      // a fixed set — everything recorded before the machine attached — and it
      // genuinely finishes. The capture lane does not: its subject grows with
      // every live session that fails to forward, so `phase` can go back to
      // 'filling' after reading 'complete'. This keeps its original meaning
      // either way — the first moment this machine owed the deployment nothing —
      // which is why it is pinned rather than recomputed.
      // WRITTEN ONCE, on the false→true transition, and never cleared. Under v1
      // this was monotone because the structural lane only ever drained; the
      // capture lane is what makes `done` flap, and clearing on every flap would
      // erase the pin and re-stamp it on the next catch-up — so a consumer
      // reading "when this machine first caught up" would get the most recent
      // one instead. Carrying the previous value through the false case is what
      // keeps the original meaning.
      completedAtMs: previous?.completedAtMs ?? (done ? result.atMs : null),
    });
    return result.outcome;
  } catch {
    // Nothing to report to and nowhere to report it.
    return 'failed';
  }
}
