import type { DatabaseSync, StatementSync } from 'node:sqlite';

import { CAPTURE_EVENT_TYPES_SQL } from '@akasecurity/schema';

import { withTransaction } from '../internal/transactions.ts';

/**
 * Local body expiry: clears `audit_events.content` past a retention horizon and
 * stamps `content_expired_at`.
 *
 * It expires the BODY, never the ROW. The event, its timestamps, severity,
 * action_taken and repo, and every `inspection_findings` row derived from it are
 * left untouched — which is why `audit_events` stays an unbounded table rather
 * than joining the two swept ones. Deleting rows would cascade into the findings
 * and erase the security history this product exists to keep; the bodies are
 * where the bytes are, and almost none of the bytes are where the meaning is.
 *
 * THE SYNC LANE IS THE PART THAT CAN LOSE SOMEBODY ELSE'S DATA, and it is not
 * symmetric across event kinds. `prompt`/`response`/`tool_use` are the kinds an
 * attached machine forwards to the deployment its settings name, and a row is
 * owed until `synced_at` is stamped — `-1` for a permanent skip, a timestamp for
 * a delivery. `code_change` is structurally excluded from that drain, so no
 * amount of sync state makes one of those rows owed.
 *
 * A row on the sync lane whose `synced_at` is NULL is therefore NOT safe to
 * expire merely because nothing is currently claiming it: `aka sync-history --on`
 * can retroactively claim the backlog at any later time, with no age bound at
 * all. So the lane is gated by the caller rather than guessed at here —
 * `sweepSyncLane` is false whenever an attach or a history-sync consent could
 * still make those rows owed, and expiring them then is refused outright.
 *
 * `content_hash` is deliberately preserved. It costs none of the reclaimable
 * bytes, it is what backfill idempotency is keyed on, and clearing it would make
 * an expired row look re-ingestable.
 */

/** What one pass did, and whether there is more left to do. */
export interface BodyExpiryOutcome {
  /** Rows whose body was cleared. */
  readonly rowsExpired: number;
  /** Bytes of body text those rows were holding, measured before the clear. */
  readonly bytesFreed: number;
  /**
   * Rows past the horizon that were NOT expired because the sync lane still
   * owes them. Reported rather than silently skipped: a user who set a 30-day
   * horizon and sees nothing reclaimed is owed the reason.
   */
  readonly rowsHeldBySync: number;
  /** False when the pass hit its row cap and more candidates remain. */
  readonly done: boolean;
}

export interface BodyExpiryOptions {
  /** Bodies on events older than this instant are candidates. */
  readonly cutoff: number;
  /**
   * Whether `prompt`/`response`/`tool_use` bodies with no `synced_at` may be
   * expired. FALSE on any machine where an attach or a history-sync consent
   * could still make them owed; the caller decides, because that depends on
   * settings this module does not read.
   */
  readonly sweepSyncLane: boolean;
  /** Stamped into `content_expired_at`. */
  readonly now: number;
  /** Hard cap per pass, so a first run on a large store stays bounded. */
  readonly maxRows?: number;
  /** Rows per transaction. */
  readonly batchSize?: number;
}

/**
 * Batch size and per-pass cap.
 *
 * Both exist to keep the sweep from starving the hook writers it shares the file
 * with. `openWithPragmas` gives every connection a 2s `busy_timeout`, and
 * `recordCapture` is fail-open — so a sweep that holds one long write
 * transaction does not merely slow a hook down, it makes that hook silently
 * drop a capture. Small transactions with the lock released between them is the
 * shape that avoids it.
 */
const DEFAULT_BATCH_SIZE = 500;
const DEFAULT_MAX_ROWS = 50_000;

/** The kinds an attached machine forwards, and which are therefore lane-gated. */
const SYNC_LANE_TYPES_SQL = `'prompt','response','tool_use'`;

export class SqliteBodyRetentionRepository {
  private readonly candidatesStmt: StatementSync;
  private readonly candidatesSyncSafeStmt: StatementSync;
  private readonly heldBySyncStmt: StatementSync;
  private readonly expireStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // LENGTH over the CAST, never over the TEXT: LENGTH() on a TEXT value stops
    // at the first embedded NUL, and real capture bodies carry them — measured
    // 134,576 such rows on one store, where the text form under-reported a
    // 1.79 MB body as 9 characters. The byte figure is the whole point of the
    // sweep, so it has to be the byte figure.
    const select = (laneClause: string) => `
      SELECT id, LENGTH(CAST(content AS BLOB)) AS bytes
        FROM audit_events
       WHERE content IS NOT NULL
         AND started_at < :cutoff
         AND event_type IN (${CAPTURE_EVENT_TYPES_SQL})
         ${laneClause}
       ORDER BY started_at
       LIMIT :limit`;

    this.candidatesStmt = this.db.prepare(select(''));
    // `synced_at IS NOT NULL` covers both dispositions that end the obligation:
    // a delivery timestamp and the `-1` permanent-skip sentinel.
    this.candidatesSyncSafeStmt = this.db.prepare(
      select(`AND (event_type NOT IN (${SYNC_LANE_TYPES_SQL}) OR synced_at IS NOT NULL)`),
    );
    this.heldBySyncStmt = this.db.prepare(`
      SELECT COUNT(*) AS n
        FROM audit_events
       WHERE content IS NOT NULL
         AND started_at < :cutoff
         AND event_type IN (${SYNC_LANE_TYPES_SQL})
         AND synced_at IS NULL`);
    // content_hash is NOT cleared — see the module comment.
    this.expireStmt = this.db.prepare(
      `UPDATE audit_events SET content = NULL, content_expired_at = :now WHERE id = :id`,
    );
  }

  /** How many bytes a pass with these options would free, changing nothing. */
  preview(opts: Omit<BodyExpiryOptions, 'now'>): Omit<BodyExpiryOutcome, 'done'> {
    const limit = opts.maxRows ?? DEFAULT_MAX_ROWS;
    const stmt = opts.sweepSyncLane ? this.candidatesStmt : this.candidatesSyncSafeStmt;
    const rows = stmt.all({ cutoff: opts.cutoff, limit }) as { id: string; bytes: number }[];
    return {
      rowsExpired: rows.length,
      bytesFreed: rows.reduce((sum, r) => sum + r.bytes, 0),
      rowsHeldBySync: this.countHeldBySync(opts),
    };
  }

  /** Clear eligible bodies, in bounded batches. */
  expire(opts: BodyExpiryOptions): BodyExpiryOutcome {
    const batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
    const maxRows = opts.maxRows ?? DEFAULT_MAX_ROWS;
    const stmt = opts.sweepSyncLane ? this.candidatesStmt : this.candidatesSyncSafeStmt;

    let rowsExpired = 0;
    let bytesFreed = 0;
    let done = true;

    while (rowsExpired < maxRows) {
      const remaining = Math.min(batchSize, maxRows - rowsExpired);
      const batch = stmt.all({ cutoff: opts.cutoff, limit: remaining }) as {
        id: string;
        bytes: number;
      }[];
      if (batch.length === 0) break;

      // One transaction per batch, and the lock is released between them. The
      // candidate query re-runs each time rather than paging a cursor: the
      // predicate is self-limiting, because a row this loop clears stops
      // matching `content IS NOT NULL` and cannot come back.
      // IMMEDIATE: take the write lock up front rather than upgrading into it
      // mid-transaction, where the upgrade can fail against a concurrent writer
      // after work is already done.
      withTransaction(
        this.db,
        () => {
          for (const row of batch) this.expireStmt.run({ id: row.id, now: opts.now });
        },
        'IMMEDIATE',
      );

      rowsExpired += batch.length;
      bytesFreed += batch.reduce((sum, r) => sum + r.bytes, 0);

      if (batch.length < remaining) break;
      if (rowsExpired >= maxRows) {
        // Cap reached rather than candidates exhausted — say so, so a caller
        // running to completion knows to come back.
        done = stmt.all({ cutoff: opts.cutoff, limit: 1 }).length === 0;
      }
    }

    return { rowsExpired, bytesFreed, rowsHeldBySync: this.countHeldBySync(opts), done };
  }

  private countHeldBySync(opts: { cutoff: number; sweepSyncLane: boolean }): number {
    if (opts.sweepSyncLane) return 0;
    const row = this.heldBySyncStmt.get({ cutoff: opts.cutoff }) as { n: number };
    return row.n;
  }
}
