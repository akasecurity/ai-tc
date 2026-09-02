import { dataDir, defaultDataDir, settingsDir } from '@akasecurity/persistence';

import { readHistorySyncState, writeHistorySyncState } from './history-state.ts';
import { runHistorySync } from './history-sync.ts';

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
 * A null result means NO PASS WAS MADE — not attached, no grant, the breaker is
 * open, or another drain holds the claim — and nothing is written for it. That
 * is distinct from every recorded outcome, each of which describes something a
 * deployment did, and writing one would re-create a file a detach just removed.
 */
export async function runHistorySyncPass(base: string = defaultDataDir()): Promise<void> {
  try {
    const dir = dataDir(base);
    const result = await runHistorySync({
      base,
      settingsDir: settingsDir(base),
      dataDir: dir,
    });
    if (result === null) return;

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
      skippedTotal: result.counts.skipped,
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
      completedAtMs: done ? (previous?.completedAtMs ?? result.atMs) : null,
    });
  } catch {
    // Nothing to report to and nowhere to report it.
  }
}
