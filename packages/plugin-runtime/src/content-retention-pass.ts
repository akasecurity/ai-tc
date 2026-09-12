import { dataDir, defaultDataDir, openLocalDatabase } from '@akasecurity/persistence';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import { canSweepSyncLane } from '@akasecurity/schema';

/**
 * How many bodies one pass may clear.
 *
 * A cap rather than "until done", because the first pass on a store that has
 * been accumulating for months has hundreds of thousands of candidates and this
 * child shares the file with live hook writers. Bounded work per pass, repeated
 * hourly, reaches the same steady state without ever holding the write lock
 * long enough to make a capture fail open.
 */
const MAX_ROWS_PER_SWEEP = 50 * 1000;

/** What one pass did, or why it made none. */
export type ContentRetentionReport =
  | {
      readonly ran: true;
      readonly rowsExpired: number;
      readonly bytesFreed: number;
      readonly done: boolean;
    }
  | { readonly ran: false; readonly reason: 'disabled' | 'unreadable' };

const DAY_MS = 86_400_000;

export interface ContentRetentionPassSeams {
  readonly base?: string;
  readonly now?: () => number;
}

/**
 * The detached child's whole program for local body expiry.
 *
 * Each harness ships a short entry that imports this and calls it, so the sweep
 * is written once here rather than three times in three plugin trees.
 * `triggerContentRetention` is what spawns those entries.
 *
 * NEVER THROWS. It runs detached with stdio ignored and no parent watching, so
 * a rejection would be an unhandled rejection nobody ever sees. A failure here
 * costs a pass; the next session starts another.
 *
 * THE SETTING IS RE-READ HERE, not trusted from the parent. The trigger checked
 * it to avoid paying a spawn, but this process starts some milliseconds later
 * and the answer is the user's to change at any moment — and the thing being
 * decided is whether to destroy data.
 */
export function runContentRetentionPass(
  seams: ContentRetentionPassSeams = {},
): ContentRetentionReport {
  const base = seams.base ?? defaultDataDir();
  const now = (seams.now ?? Date.now)();
  try {
    const settings = readWorkspaceSettings(base);
    const retention = settings.bodyRetention;
    if (!retention.enabled) return { ran: false, reason: 'disabled' };

    const db = openLocalDatabase(dataDir(base));
    const out = db.bodyRetention.expire({
      cutoff: now - retention.retainDays * DAY_MS,
      sweepSyncLane: canSweepSyncLane(settings),
      now,
      maxRows: MAX_ROWS_PER_SWEEP,
    });
    return { ran: true, rowsExpired: out.rowsExpired, bytesFreed: out.bytesFreed, done: out.done };
  } catch {
    // An unreadable settings file or an unopenable store is a pass not made,
    // never a thrown error out of a process nobody is watching.
    return { ran: false, reason: 'unreadable' };
  }
}
