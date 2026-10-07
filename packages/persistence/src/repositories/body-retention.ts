import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { SyncLaneRetention } from '@akasecurity/schema';
import { CAPTURE_EVENT_TYPES_SQL } from '@akasecurity/schema';

import { OUTBOX_CAPTURE_TYPE_LIST } from '../internal/outbox-lane.ts';
import { withTransaction } from '../internal/transactions.ts';

/**
 * Local body expiry: clears `audit_events.content` past a retention horizon and
 * stamps `content_expired_at`.
 *
 * It expires the BODY, never the ROW. The event, its timestamps, severity,
 * action_taken and repo, and every `inspection_findings` row derived from it are
 * kept — which is why `audit_events` stays an unbounded table rather than
 * joining the two swept ones. The one thing a finding loses is its masked
 * excerpt (`context`): it is a copy of the body's lines, so it goes when the
 * body does. Its line and column stay, as position metadata. A `tool_call`
 * finding's excerpt has no body to follow, so it goes once its event is past
 * the same horizon. Deleting rows would cascade into the findings
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
 * `sweepSyncLane` says which of those rows could still be owed, and expiring
 * one of them is refused outright. What could still be owed follows the
 * attachment. On a scoped attachment, with or without a history-sync grant, it is
 * the rows stamped with an enrolled `scope_key`, plus any row still marked owed
 * (a machine attachment's undelivered forward leaves that marker on a row of any
 * key, and enrolling its repository later makes it reachable): the grant there
 * covers the enrolled repositories, never the whole lane. On a machine
 * attachment, under a grant with no scoped attachment, or whenever the
 * credential or its scope record cannot be trusted, it is every unsynced row.
 *
 * `content_hash` is deliberately preserved. It costs none of the reclaimable
 * bytes, it is what backfill idempotency is keyed on, and clearing it would make
 * an expired row look re-ingestable.
 */

/** What one pass did, and whether there is more left to do. */
export interface BodyExpiryOutcome {
  /** Rows whose body was cleared. */
  readonly rowsExpired: number;
  /**
   * Bytes of body text those rows were holding, measured before the clear.
   * Finding excerpts the same pass clears are deliberately outside this and
   * `rowsExpired`: each is capped at five short lines, and the rows they sit
   * on (a `tool_call`, or a body an earlier pass expired) are not body rows.
   */
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
   * What the sync lane — `prompt`/`response`/`tool_use` bodies with no
   * `synced_at` — may lose on this pass, as `syncLaneRetentionOf` decides it:
   *
   *   - `sweep`: nothing could make those rows owed, so they age out like any
   *     other body;
   *   - `hold-all`: an attach or a history-sync grant could still claim any of
   *     them, so none is expired;
   *   - `hold-keys`: a scoped attachment owes the rows stamped with one of its
   *     keys, and any row still marked owed, so those are held and every other
   *     one ages out.
   *
   * `true` and `false` are the two-state gate this option was before scoped
   * attachments, and read as `sweep` and `hold-all`. The caller decides,
   * because the answer depends on settings and a credential this module does
   * not read.
   */
  readonly sweepSyncLane: boolean | SyncLaneRetention;
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

/**
 * The kinds an attached machine forwards, and which are therefore lane-gated.
 *
 * Taken from the drain's own list rather than written out beside it. The two
 * decide opposite things from the same vocabulary — that one what to SEND, this
 * one what may not be EXPIRED until sent — so a kind added there has to move
 * this gate in the same commit. Duplicated, adding `code_change` to the drain
 * would start owing those bodies while this gate went on clearing them.
 */
const SYNC_LANE_TYPES_SQL = OUTBOX_CAPTURE_TYPE_LIST;

/** The two answers `true` and `false` stood for before scoped attachments. */
const SWEEP: SyncLaneRetention = { kind: 'sweep' };
const HOLD_ALL: SyncLaneRetention = { kind: 'hold-all' };

export class SqliteBodyRetentionRepository {
  private readonly candidatesStmt: StatementSync;
  private readonly candidatesSyncSafeStmt: StatementSync;
  private readonly candidatesScopedStmt: StatementSync;
  private readonly heldBySyncStmt: StatementSync;
  private readonly heldByScopeStmt: StatementSync;
  private readonly expireStmt: StatementSync;
  private readonly expireContextsStmt: StatementSync;

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
    // The scoped twin of the statement above. A scoped attachment owes the
    // unsynced sync-lane rows whose stamped key is enrolled, so a row with no
    // key, or with a key outside the list, is no more owed than a `code_change`:
    // the drain's scoped reads never return it, whatever marker it carries.
    //
    // EXCEPT A ROW STILL MARKED OWED (`outbox_owed = 1`), which is held whatever
    // its key. A machine attachment's live forward that did not deliver leaves
    // that marker on a row of any key, and a re-attach to the same endpoint as a
    // scoped one does not clear it. Its repository may be enrolled later, and
    // from then on the scoped drain returns it; with its body already expired it
    // could not be rebuilt and would become a permanent skip. So an owed row's
    // body outlives the sweep, until it is delivered or skipped like any other
    // unsent one. A row with no key is held too: no scope will ever return it,
    // but a machine attachment still could, and retention errs toward holding.
    // `IS NOT 1` is the exact complement of `= 1`, NULL included, because the
    // marker is NULL on every row nothing has marked.
    //
    // `scope_key IS NULL` is spelled out because `NOT IN` cannot say it. A NULL
    // key makes `scope_key NOT IN (…)` NULL rather than true, so without that arm
    // every unstamped row — all history recorded before stamping shipped — would
    // be held for ever on a machine that can never send it.
    //
    // The keys bind as ONE JSON array through json_each, so this is one
    // statement prepared here whatever the scope's size, and the recorder that
    // plan-pins it sees the statement the product runs. Comparison is BINARY,
    // the rule the in-memory verdict applies, so the two never disagree about a
    // key.
    this.candidatesScopedStmt = this.db.prepare(
      select(
        `AND (event_type NOT IN (${SYNC_LANE_TYPES_SQL}) OR synced_at IS NOT NULL
              OR (outbox_owed IS NOT 1
                  AND (scope_key IS NULL
                       OR scope_key NOT IN (SELECT value FROM json_each(:scopeKeys)))))`,
      ),
    );
    this.heldBySyncStmt = this.db.prepare(`
      SELECT COUNT(*) AS n
        FROM audit_events
       WHERE content IS NOT NULL
         AND started_at < :cutoff
         AND event_type IN (${SYNC_LANE_TYPES_SQL})
         AND synced_at IS NULL`);
    // The exact complement, within the sync lane, of what the scoped candidates
    // statement lets through: unsynced AND (still marked owed OR stamped with an
    // enrolled key).
    this.heldByScopeStmt = this.db.prepare(`
      SELECT COUNT(*) AS n
        FROM audit_events
       WHERE content IS NOT NULL
         AND started_at < :cutoff
         AND event_type IN (${SYNC_LANE_TYPES_SQL})
         AND synced_at IS NULL
         AND (outbox_owed = 1
              OR scope_key IN (SELECT value FROM json_each(:scopeKeys)))`);
    // content_hash is NOT cleared — see the module comment.
    this.expireStmt = this.db.prepare(
      `UPDATE audit_events SET content = NULL, content_expired_at = :now WHERE id = :id`,
    );
    // Excerpts on findings whose event is past the horizon and holds no body:
    // a body this pass (or an earlier one) cleared, or an event that never had
    // one. A body the sync lane still holds keeps its findings' excerpts too.
    // Seeks the partial index over excerpt-holding findings by first
    // detection — which can only precede the event's start, so the range never
    // misses a candidate — and checks the event's own time as a residual.
    this.expireContextsStmt = this.db.prepare(
      `UPDATE inspection_findings SET context = NULL
        WHERE id IN (
          SELECT f.id
            FROM inspection_findings f INDEXED BY idx_inspection_findings_context
            JOIN audit_events e ON e.id = f.audit_event_id
           WHERE f.context IS NOT NULL
             AND f.first_detected_at < :cutoff
             AND e.content IS NULL
             AND e.started_at < :cutoff
           LIMIT :limit)`,
    );
  }

  /**
   * How many body bytes a pass with these options would free, changing
   * nothing. Finding excerpts are not counted (see `bytesFreed`).
   */
  preview(opts: Omit<BodyExpiryOptions, 'now'>): Omit<BodyExpiryOutcome, 'done'> {
    const lane = laneOf(opts.sweepSyncLane);
    const rows = this.candidates(lane, opts.cutoff, opts.maxRows ?? DEFAULT_MAX_ROWS);
    return {
      rowsExpired: rows.length,
      bytesFreed: rows.reduce((sum, r) => sum + r.bytes, 0),
      rowsHeldBySync: this.countHeldBySync(lane, opts.cutoff),
    };
  }

  /** Clear eligible bodies, in bounded batches. */
  expire(opts: BodyExpiryOptions): BodyExpiryOutcome {
    const batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
    const maxRows = opts.maxRows ?? DEFAULT_MAX_ROWS;
    const lane = laneOf(opts.sweepSyncLane);

    let rowsExpired = 0;
    let bytesFreed = 0;
    let done = true;

    while (rowsExpired < maxRows) {
      const remaining = Math.min(batchSize, maxRows - rowsExpired);
      const batch = this.candidates(lane, opts.cutoff, remaining);
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
        done = this.candidates(lane, opts.cutoff, 1).length === 0;
      }
    }

    this.expireContexts(opts.cutoff, batchSize, maxRows);

    return {
      rowsExpired,
      bytesFreed,
      rowsHeldBySync: this.countHeldBySync(lane, opts.cutoff),
      done,
    };
  }

  // Clear the excerpts that outlived their body, one bounded transaction per
  // batch for the same reason the body sweep batches, and at most `maxRows` of
  // them per pass under the same cap: the next pass picks up the rest.
  private expireContexts(cutoff: number, batchSize: number, maxRows: number): void {
    let total = 0;
    while (total < maxRows) {
      const limit = Math.min(batchSize, maxRows - total);
      let cleared = 0;
      withTransaction(
        this.db,
        () => {
          cleared = Number(this.expireContextsStmt.run({ cutoff, limit }).changes);
        },
        'IMMEDIATE',
      );
      total += cleared;
      if (cleared < limit) return;
    }
  }

  /**
   * One batch of candidates under `lane`, bound with exactly the parameters its
   * statement names — node:sqlite refuses a named parameter a statement does not
   * declare, so the key list goes to the scoped statements only.
   *
   * Anything that is not `sweep` or `hold-keys` takes the hold-all statement.
   * The type admits no fourth kind, but this decides what is destroyed, and the
   * direction an unforeseen value falls has to be holding.
   */
  private candidates(
    lane: SyncLaneRetention,
    cutoff: number,
    limit: number,
  ): { id: string; bytes: number }[] {
    const rows =
      lane.kind === 'sweep'
        ? this.candidatesStmt.all({ cutoff, limit })
        : lane.kind === 'hold-keys'
          ? this.candidatesScopedStmt.all({ cutoff, limit, scopeKeys: JSON.stringify(lane.keys) })
          : this.candidatesSyncSafeStmt.all({ cutoff, limit });
    return rows as { id: string; bytes: number }[];
  }

  private countHeldBySync(lane: SyncLaneRetention, cutoff: number): number {
    if (lane.kind === 'sweep') return 0;
    const row = (
      lane.kind === 'hold-keys'
        ? this.heldByScopeStmt.get({ cutoff, scopeKeys: JSON.stringify(lane.keys) })
        : this.heldBySyncStmt.get({ cutoff })
    ) as { n: number };
    return row.n;
  }
}

/** The caller's lane decision, with the two-state spellings read as their kinds. */
function laneOf(gate: boolean | SyncLaneRetention): SyncLaneRetention {
  if (gate === true) return SWEEP;
  if (gate === false) return HOLD_ALL;
  return gate;
}
