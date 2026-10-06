import {
  dataDir,
  defaultDataDir,
  openLocalDatabase,
  readControlPlaneCredentialFile,
  settingsDir,
} from '@akasecurity/persistence';
import { readWorkspaceSettings } from '@akasecurity/persistence';
import type { SyncLaneRetention, WorkspaceSettings } from '@akasecurity/schema';
import {
  attachmentModeOf,
  isAttached,
  resolveScope,
  syncLaneRetentionOf,
} from '@akasecurity/schema';

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

/**
 * What the sync lane may lose on this machine, from the settings in force and
 * the attachment mode its credential records.
 *
 * The mode is read off the credential, not the settings, because that is where
 * an attachment records it and no settings writer can remove it.
 * `syncLaneRetentionOf` owns the answer; this only gathers its two inputs.
 *
 * ONE HELPER, asked by both the background pass and `aka prune`. It decides
 * which bodies are destroyed, so the two callers share this function rather
 * than each keeping a copy that could drift, and they cannot disagree about
 * which bodies a deployment is still owed.
 *
 * TOTAL, and every failure holds. An attachment whose credential cannot be read
 * resolves to no scope, which `syncLaneRetentionOf` reads as hold-all, and a
 * throw anywhere here is hold-all too, so neither caller needs a catch of its
 * own around it. Holding a body costs disk; expiring one an organization was
 * owed cannot be undone.
 */
export function syncLaneRetentionFor(settings: WorkspaceSettings, base: string): SyncLaneRetention {
  try {
    const connection = settings.controlPlane;
    if (!isAttached(settings) || connection === undefined) {
      return syncLaneRetentionOf(settings, undefined);
    }
    const read = readControlPlaneCredentialFile(settingsDir(base), connection);
    if (!read.usable) return syncLaneRetentionOf(settings, undefined);
    return syncLaneRetentionOf(
      settings,
      resolveScope({
        mode: attachmentModeOf(read.credential),
        scope: settings.attachmentScope,
        endpoint: connection.endpoint,
      }),
    );
  } catch {
    return { kind: 'hold-all' };
  }
}

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

    const syncLane = syncLaneRetentionFor(settings, base);
    const db = openLocalDatabase(dataDir(base));
    const out = db.bodyRetention.expire({
      cutoff: now - retention.retainDays * DAY_MS,
      sweepSyncLane: syncLane,
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
