import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { AuditEventRow } from '@akasecurity/schema';

import { allRows, getRow } from '../internal/rows.ts';
import { withTransaction } from '../internal/transactions.ts';

/**
 * The event types this drain will ever send.
 *
 * The whole scope of the feature is here: structural activity only. Capture
 * rows — the ones carrying prompt and response text in `content` — are excluded
 * by construction rather than by a filter someone could widen, which is why this
 * list is the single place the set is written down.
 */
export const STRUCTURAL_EVENT_TYPES = ['session', 'llm_call', 'tool_call'] as const;

const TYPE_LIST = STRUCTURAL_EVENT_TYPES.map((t) => `'${t}'`).join(', ');

/**
 * The capture grain — the rows STRUCTURAL_EVENT_TYPES exists to keep out.
 *
 * A SEPARATE list, deliberately, and never merged into the one above. The two
 * lanes are not two settings of one drain: they carry different wire shapes to
 * different routes, and only one of them may carry `content`.
 *
 *   structural → RecordAuditEventRequest → POST /v1/audit-events
 *                The receiver PERSISTS `content` verbatim, so rebuildAuditEvent
 *                drops it and this lane must never carry a capture.
 *   capture    → IngestEvent            → POST /v1/events
 *                The receiver scans `content` in memory and stores NULL, so this
 *                is the only route a prompt's text may take.
 *
 * Widening the structural list to "just include captures" is therefore not a
 * shortcut, it is a data leak with a green test suite: rebuildAuditEvent has no
 * `content` key, so captures would arrive stripped of the text that is their
 * whole point, be stamped delivered, and never be offered again — while the
 * route that received them wrote every other field to disk for keeps.
 *
 * `code_change` IS A CAPTURE KIND AND IS DELIBERATELY ABSENT from the list
 * below. No hook
 * writes one — the only two writers are the scanners (local-ops' fs-scan, behind
 * `aka scan` and the dashboard's folder scan, and packages/scanner's worktree
 * scan) — and its `content` is the COMPLETE SOURCE FILE, redacted only at
 * detected spans, gitignored scratch included. Two things follow, each
 * disqualifying on its own:
 *
 *   It is not what the grant describes. Every disclosure surface enumerates the
 *   text-carrying payload as a prompt, an assistant reply or a tool result.
 *   Whole proprietary source files appear in none of them.
 *
 *   It would not be a RETRY. fs-scan takes a LocalDatabase and calls
 *   recordCapture directly, never through AttachedDataGateway, so those rows
 *   have never been offered to the live path at any release. Draining them is
 *   first-time egress, under copy saying this setting only decides whether an
 *   undelivered item is kept or dropped.
 *
 * Adding it is one word here — and it is a product decision that owes its own
 * disclosure, not a completeness fix.
 */
// MODULE-PRIVATE, and named for the lane rather than for the grain, because
// `@akasecurity/schema` already exports a `CAPTURE_EVENT_TYPES_SQL` derived from
// `EventKind` — FOUR kinds, `code_change` included, with the opposite drift
// policy — and several reads in this very package interpolate it. Exporting a
// three-kind constant under the neighbouring name would put both on the
// package's public surface, where a later findings read reaching for the wrong
// one silently loses `code_change` and under-reports with nothing failing.
const OUTBOX_CAPTURE_EVENT_TYPES = ['prompt', 'response', 'tool_use'] as const;

const CAPTURE_TYPE_LIST = OUTBOX_CAPTURE_EVENT_TYPES.map((t) => `'${t}'`).join(', ');

/** `synced_at` values that are not a delivery time. */
const SKIPPED = -1;

/** How many structural rows are delivered, waiting, or permanently skipped. */
export interface HistorySyncCounts {
  pending: number;
  sent: number;
  skipped: number;
}

/**
 * Every tracked row, in exactly one delivery state.
 *
 * Distinct from `counts()`, which is the DRAIN's view and does not partition:
 * its `pending` is bounded by the backlog boundary while `sent` and `skipped`
 * are lifetime totals, so rows recorded after the boundary appear in none of
 * the three and the numbers do not sum to anything. These four do sum to
 * `total`, which is what a surface reporting delivery state needs.
 *
 * SCOPE, and the caveat that follows from it: every column here is measured
 * over STRUCTURAL rows only — `partitionStmt` carries the same
 * `event_type IN (…)` filter as the rest of this ledger. Capture rows are not
 * counted in `total`, so this is the delivery state of the structural lane, not
 * of everything the machine owes a deployment.
 *
 * That scope is why `markCaptureDelivered` does NOT settle anything visible
 * here. It stamps a capture row, through the same UPDATE a drain uses, so the
 * two are indistinguishable afterwards — but this query never counts capture
 * rows, so the stamp is invisible to it by construction. The stamp exists for a
 * capture drain to read; it is not a fix for this read.
 *
 * `queued` therefore still OVER-COUNTS on an attached machine, and by the same
 * rows it always did: a structural row the live path forwarded successfully
 * (`recordToolCalls`) is never stamped by anything, so it stays NULL and reads
 * as owed. Closing that needs a stamp on the structural forward, which no path
 * does today. Read `queued` as "not known to have been delivered", not as
 * "undelivered".
 */
export interface HistorySyncPartition {
  queued: number;
  inProgress: number;
  synced: number;
  failed: number;
  total: number;
}

/**
 * One stored detection, flattened across the finding and its rule definition.
 *
 * Shaped for the wire's ToolCallInspection but kept as a plain row: the span is
 * two columns here and one object there, so the mapping belongs to the caller
 * that owns the wire shape rather than to the store.
 */
export interface HistorySyncInspectionRow {
  ruleId: string;
  ruleName: string;
  ruleVersion: string;
  category: string;
  severity: string;
  spanStart: number;
  spanEnd: number;
  maskedMatch: string;
  actionTaken: string;
  confidence: number;
}

/** Who is draining, as the singleton row records it. */
export interface HistorySyncLease {
  ownerPid: number | null;
  ownerHost: string | null;
  acquiredAt: number | null;
  heartbeatAt: number | null;
}

const ROW_COLUMNS = `id,
   parent_id AS parentId,
   root_session_id AS rootSessionId,
   event_type AS eventType,
   host_id AS hostId,
   harness_id AS harnessId,
   source_project_id AS sourceProjectId,
   started_at AS startedAt,
   ended_at AS endedAt,
   severity,
   priority,
   content,
   content_hash AS contentHash,
   attributes`;

/**
 * The delivery ledger over `audit_events.synced_at`, and the claim that stops two
 * drains doing the same work.
 *
 * `synced_at` is a PER-ROW stamp, not a watermark, and that is load-bearing:
 * rows are inserted out of order — a reconcile pass writes an `llm_call` now
 * with a `started_at` from an hour ago — so any monotone high-water mark would
 * skip them for ever. `IS NULL` is set-based and cannot.
 *
 *   NULL              not delivered
 *   positive epoch ms delivered at that instant
 *   -1                permanently skipped; the row could not be rebuilt
 *
 * The claim is POLITENESS, NOT CORRECTNESS. Nothing in this tree can hold
 * exclusion across a network round trip, so two drains would send the same rows
 * and the far side would settle it on the row id. What the claim saves is
 * wasted request budget, and its failure mode is duplicated work, never a lost
 * or double-counted row.
 */
export class SqliteHistorySyncRepository {
  private readonly ensureRowStmt: StatementSync;
  private readonly sessionsStmt: StatementSync;
  private readonly rowsStmt: StatementSync;
  private readonly stampStmt: StatementSync;
  private readonly countsStmt: StatementSync;
  private readonly fingerprintStmt: StatementSync;
  private readonly setFingerprintStmt: StatementSync;
  private readonly rearmStmt: StatementSync;
  private readonly claimStmt: StatementSync;
  private readonly heartbeatStmt: StatementSync;
  private readonly releaseStmt: StatementSync;
  private readonly leaseStmt: StatementSync;
  private readonly inspectionsStmt: StatementSync;
  private readonly closeWindowStmt: StatementSync;
  private readonly releaseBoundaryStmt: StatementSync;
  private readonly freezeBoundaryStmt: StatementSync;
  private readonly captureRowsStmt: StatementSync;
  private readonly partitionStmt: StatementSync;
  private readonly claimRowStmt: StatementSync;
  private readonly releaseRowStmt: StatementSync;
  private readonly releaseStaleClaimsStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.ensureRowStmt = db.prepare(`INSERT OR IGNORE INTO history_sync (id) VALUES (1)`);

    // Sessions with anything left to send, oldest first. Grouped on the session
    // a row belongs to — a root's own id, a leaf's root pointer — so a session
    // whose root already went but whose leaves did not still comes back.
    this.sessionsStmt = db.prepare(
      `SELECT COALESCE(root_session_id, id) AS sessionId, MIN(started_at) AS earliest
         FROM audit_events
        WHERE synced_at IS NULL
          AND event_type IN (${TYPE_LIST})
          AND started_at < :before
        GROUP BY sessionId
        ORDER BY earliest
        LIMIT :limit`,
    );

    // ROOT FIRST, and not by convention: parent_id and root_session_id are real
    // self-referencing foreign keys on the receiving side, and nothing there
    // stubs a missing root. A leaf that arrives before its session is rejected.
    this.rowsStmt = db.prepare(
      `SELECT ${ROW_COLUMNS}
         FROM audit_events
        WHERE synced_at IS NULL
          AND event_type IN (${TYPE_LIST})
          AND started_at < :before
          AND COALESCE(root_session_id, id) = :sessionId
        ORDER BY (event_type = 'session') DESC, started_at
        LIMIT :limit`,
    );

    // Captures, flat and oldest first — NOT grouped by session, and that is a
    // property of the route rather than an oversight. /v1/events stubs a missing
    // session root on the leaf's own id, so a capture that overtakes its root is
    // absorbed rather than rejected; the structural lane pages by session only
    // because /v1/audit-events stubs nothing and its foreign keys are real.
    //
    // TWO bounds, and they are not the structural lane's.
    //
    // `:since` is the attachment boundary, and it is the INVERSE of how the
    // structural lane uses one. There, rows BEFORE the boundary are the backlog
    // to drain and rows after belong to the live path. Here, rows after it are
    // the ones the live path was supposed to deliver — so an unstamped one is
    // precisely what the outbox owes — and rows BEFORE it are pre-attach
    // history, which is the structural lane's subject and travels WITHOUT
    // `content`. Dropping this bound would drain a machine's entire local
    // history of prompts, text and all, on its first attach: covered by no
    // disclosure, since the copy says the pre-attach half sends the record of
    // activity only.
    //
    // `:before` is a GRACE WINDOW rather than a boundary. It buys quiet, not
    // correctness: it keeps this pass off rows the live forward is probably
    // still mid-flight on. A row sent twice is harmless — the receiver dedups on
    // an id derived from the row's own tuple — so it may be small.
    this.captureRowsStmt = db.prepare(
      `SELECT ${ROW_COLUMNS}
         FROM audit_events
        WHERE synced_at IS NULL
          AND sync_claimed_at IS NULL
          AND event_type IN (${CAPTURE_TYPE_LIST})
          AND started_at >= :since
          AND started_at < :before
        ORDER BY started_at
        LIMIT :limit`,
    );

    // Settling clears the claim in the same statement. A row that has a
    // delivery time and still reads as claimed would show up in two states at
    // once, and the pair is only ever written together.
    this.stampStmt = db.prepare(
      `UPDATE audit_events SET synced_at = :at, sync_claimed_at = NULL WHERE id = :id`,
    );

    // Claim only what is still unsent: a row that settled between the read and
    // this write must not be dragged back into the in-flight state.
    this.claimRowStmt = db.prepare(
      `UPDATE audit_events SET sync_claimed_at = :at WHERE id = :id AND synced_at IS NULL`,
    );
    this.releaseRowStmt = db.prepare(
      `UPDATE audit_events SET sync_claimed_at = NULL WHERE id = :id`,
    );
    // A drain killed mid-batch leaves rows claimed for ever, and a claim that is
    // never cleared reads as "sending" indefinitely. Nothing recovers it on its
    // own — the claim is per-row bookkeeping, not the lease — so a caller sweeps
    // stale ones the same way the lease treats a stale heartbeat.
    this.releaseStaleClaimsStmt = db.prepare(
      `UPDATE audit_events SET sync_claimed_at = NULL
        WHERE sync_claimed_at IS NOT NULL AND sync_claimed_at < :staleBefore`,
    );

    // The four states are written to be EXHAUSTIVE, so they always sum to
    // total. `failed` is `IS NOT NULL AND <= 0` rather than `= -1` for that
    // reason: the ledger only ever writes -1 there, but a row is better counted
    // as failed than silently missing from a rendered breakdown.
    this.partitionStmt = db.prepare(
      `SELECT
         SUM(CASE WHEN synced_at IS NULL AND sync_claimed_at IS NULL THEN 1 ELSE 0 END) AS queued,
         SUM(CASE WHEN synced_at IS NULL AND sync_claimed_at IS NOT NULL THEN 1 ELSE 0 END) AS inProgress,
         SUM(CASE WHEN synced_at > 0 THEN 1 ELSE 0 END) AS synced,
         SUM(CASE WHEN synced_at IS NOT NULL AND synced_at <= 0 THEN 1 ELSE 0 END) AS failed,
         COUNT(*) AS total
       FROM audit_events
       WHERE event_type IN (${TYPE_LIST})`,
    );

    this.countsStmt = db.prepare(
      `SELECT
         SUM(CASE WHEN synced_at IS NULL AND started_at < :before THEN 1 ELSE 0 END) AS pending,
         SUM(CASE WHEN synced_at > 0 THEN 1 ELSE 0 END) AS sent,
         SUM(CASE WHEN synced_at = ${String(SKIPPED)} THEN 1 ELSE 0 END) AS skipped
       FROM audit_events
       WHERE event_type IN (${TYPE_LIST})`,
    );

    this.fingerprintStmt = db.prepare(
      `SELECT endpoint_fingerprint AS fingerprint, backlog_before AS backlogBefore,
              capture_floor AS captureFloor
         FROM history_sync WHERE id = 1`,
    );
    this.setFingerprintStmt = db.prepare(
      `UPDATE history_sync
          SET endpoint_fingerprint = :fingerprint, backlog_before = :backlogBefore,
              capture_floor = :backlogBefore
        WHERE id = 1`,
    );
    // Permanent skips are NOT re-armed: a row that failed to rebuild locally
    // fails the same way against any deployment.
    // STRUCTURAL ONLY, and the capture half is deliberately absent — it was
    // added here and then removed, so the reasoning is worth keeping.
    //
    // Re-arming exists because a stamp records that ONE deployment received a
    // row, and the next one has not. That argument holds for the structural
    // lane, which reads `started_at < :before` and so re-drains the rows the
    // re-arm just cleared. It does NOT hold for captures, which read the other
    // side of the same boundary (`started_at >= :since`): every row a
    // deployment change re-arms was recorded before the new attachment, so the
    // capture lane would never offer one again. Widening this achieved nothing
    // but un-stamping delivered rows for ever.
    //
    // And re-offering them would be WRONG, which is why the fix is to narrow
    // rather than to loosen the bound. A capture recorded under deployment A is
    // pre-attach relative to B, and the grant says the pre-attach half sends the
    // record of activity, not its text. B is entitled to the structural rows —
    // which it gets, because those DO re-arm — and not to the prompts.
    this.rearmStmt = db.prepare(
      `UPDATE audit_events SET synced_at = NULL
        WHERE synced_at > 0 AND event_type IN (${TYPE_LIST})`,
    );

    // A heartbeat in the FUTURE counts as stale. A backwards clock correction
    // would otherwise strand the claim until the clock caught up again, which
    // on a large correction is indistinguishable from never.
    this.claimStmt = db.prepare(
      `UPDATE history_sync
          SET owner_pid = :pid, owner_host = :host, acquired_at = :now, heartbeat_at = :now
        WHERE id = 1
          AND (owner_pid IS NULL
               OR heartbeat_at IS NULL
               OR heartbeat_at < :staleBefore
               OR heartbeat_at > :now)`,
    );
    this.heartbeatStmt = db.prepare(
      `UPDATE history_sync SET heartbeat_at = :now WHERE id = 1 AND owner_pid = :pid`,
    );
    this.releaseStmt = db.prepare(
      `UPDATE history_sync
          SET owner_pid = NULL, owner_host = NULL, acquired_at = NULL, heartbeat_at = NULL
        WHERE id = 1 AND owner_pid = :pid`,
    );
    // Everything still unsent from the period the machine was ATTACHED. That
    // period belonged to the live forward path, delivered or dropped, and this
    // drain has never covered it — stamping it is what lets the boundary move
    // forward afterwards without re-sending any of it.
    this.closeWindowStmt = db.prepare(
      `UPDATE audit_events SET synced_at = :at
        WHERE synced_at IS NULL
          AND event_type IN (${TYPE_LIST})
          AND started_at >= :attachedAt`,
    );
    this.releaseBoundaryStmt = db.prepare(
      `UPDATE history_sync SET backlog_before = NULL WHERE id = 1`,
    );
    // The structural boundary moves; the capture floor is filled only if it has
    // never been set. COALESCE rather than a second statement, so a re-attach
    // cannot step the capture lane's floor over rows the last attachment left
    // owed — see ensureHistorySyncTable for what that would cost.
    this.freezeBoundaryStmt = db.prepare(
      `UPDATE history_sync
          SET backlog_before = :backlogBefore,
              capture_floor = COALESCE(capture_floor, :backlogBefore)
        WHERE id = 1`,
    );

    this.leaseStmt = db.prepare(
      `SELECT owner_pid AS ownerPid, owner_host AS ownerHost,
              acquired_at AS acquiredAt, heartbeat_at AS heartbeatAt
         FROM history_sync WHERE id = 1`,
    );

    // A tool call's detected secrets, joined back to the rule that found them.
    // Already masked at write time — `masked_match` is what was stored, and the
    // raw value never entered this table. Served by idx_inspection_findings_event.
    this.inspectionsStmt = db.prepare(
      `SELECT d.rule_id AS ruleId,
              d.name AS ruleName,
              d.version AS ruleVersion,
              d.category AS category,
              d.severity AS severity,
              f.span_start AS spanStart,
              f.span_end AS spanEnd,
              f.masked_match AS maskedMatch,
              f.action_taken AS actionTaken,
              f.confidence AS confidence
         FROM inspection_findings f
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
        WHERE f.audit_event_id = :auditEventId
        ORDER BY f.span_start, f.id`,
    );
  }

  /**
   * The masked detections recorded against one tool call.
   *
   * These travel with the event because a tool call's target is not
   * re-inspectable from the event alone — unlike a capture, where the text
   * itself is re-scannable. What crosses is the masked match and the rule that
   * produced it, never the value.
   */
  inspectionsFor(auditEventId: string): HistorySyncInspectionRow[] {
    return allRows<HistorySyncInspectionRow>(this.inspectionsStmt, { auditEventId });
  }

  /**
   * Sessions with structural rows still to send, oldest first.
   *
   * BOUNDED BY THE BACKLOG BOUNDARY, which is the whole correctness of this
   * read. Anything recorded after the machine attached is the live forward
   * path's to deliver; this drain exists for what was recorded before it, and a
   * row both paths send is at best a duplicate request and at worst — for a
   * session root — an overwrite of the inventory ids the live path resolved.
   */
  pendingSessions(limit: number, before: number): string[] {
    return allRows<{ sessionId: string }>(this.sessionsStmt, { limit, before }).map(
      (r) => r.sessionId,
    );
  }

  /** One session's undelivered structural rows within the backlog, root first. */
  pendingRows(sessionId: string, limit: number, before: number): AuditEventRow[] {
    return allRows<AuditEventRow>(this.rowsStmt, { sessionId, limit, before });
  }

  /**
   * Captures this machine still owes the deployment, oldest first.
   *
   * `since` is the attachment boundary — only captures from the period this
   * machine was attached, because those are the ones a live forward owed and
   * failed to deliver. Anything older is pre-attach history, which travels on
   * the structural lane without its text. `before` is the grace window. See
   * captureRowsStmt for why the two bounds point the way they do.
   */
  pendingCaptureRows(limit: number, since: number, before: number): AuditEventRow[] {
    return allRows<AuditEventRow>(this.captureRowsStmt, { limit, since, before });
  }

  /** Record delivery. Called only AFTER the far side has accepted the rows. */
  markSynced(ids: readonly string[], atMs: number): void {
    this.stampAll(ids, atMs);
  }

  /**
   * Record that a row will never be sent.
   *
   * Reserved for a local defect — a row that cannot be rebuilt into a valid
   * payload. A row that merely failed to reach the deployment stays NULL, so it
   * is retried; marking those would turn one outage into permanent data loss.
   */
  markSkipped(ids: readonly string[]): void {
    this.stampAll(ids, SKIPPED);
  }

  private eachInTransaction(ids: readonly string[], run: (id: string) => void): void {
    if (ids.length === 0) return;
    withTransaction(
      this.db,
      () => {
        for (const id of ids) run(id);
      },
      'IMMEDIATE',
    );
  }

  private stampAll(ids: readonly string[], value: number): void {
    if (ids.length === 0) return;
    // One short IMMEDIATE transaction: the write lock is taken up front rather
    // than upgraded mid-way, so a concurrent writer meets a busy database at the
    // start instead of half-way through the stamps.
    withTransaction(
      this.db,
      () => {
        for (const id of ids) this.stampStmt.run({ at: value, id });
      },
      'IMMEDIATE',
    );
  }

  /**
   * Claim rows as in-flight.
   *
   * Advisory in exactly the sense the lease is: it records that a send is in
   * progress so a surface can say so, and a lost claim costs a row showing as
   * queued while it is actually being sent. It is not exclusion — the far side
   * settles a duplicate on the row id.
   */
  claimRows(ids: readonly string[], atMs: number): void {
    this.eachInTransaction(ids, (id) => this.claimRowStmt.run({ at: atMs, id }));
  }

  /** Give back a claim without settling — the send failed, the row is queued again. */
  releaseRows(ids: readonly string[]): void {
    this.eachInTransaction(ids, (id) => this.releaseRowStmt.run({ id }));
  }

  /**
   * Clear claims older than `staleBefore`, and report how many were cleared.
   *
   * A process killed between claiming and settling leaves rows claimed with
   * nothing left to settle them. Without this they read as "sending" for ever.
   */
  releaseStaleClaims(staleBefore: number): number {
    return Number(this.releaseStaleClaimsStmt.run({ staleBefore }).changes);
  }

  /**
   * Every tracked row in exactly one delivery state.
   *
   * Takes no boundary on purpose. The boundary answers "what should the drain
   * pick up now", which is a different question from "what state is this row
   * in" — and a machine that has never attached has no boundary to pass, so
   * requiring one would force a caller to invent one and report the whole store
   * as queued.
   */
  partition(): HistorySyncPartition {
    const row = getRow<Record<keyof HistorySyncPartition, number | null>>(this.partitionStmt, {});
    return {
      queued: row?.queued ?? 0,
      inProgress: row?.inProgress ?? 0,
      synced: row?.synced ?? 0,
      failed: row?.failed ?? 0,
      total: row?.total ?? 0,
    };
  }

  /** `pending` counts only what is inside the backlog; sent and skipped are totals. */
  counts(before: number): HistorySyncCounts {
    const row = getRow<{ pending: number | null; sent: number | null; skipped: number | null }>(
      this.countsStmt,
      { before },
    );
    // SUM() over no rows is NULL, which is zero of each here.
    return {
      pending: row?.pending ?? 0,
      sent: row?.sent ?? 0,
      skipped: row?.skipped ?? 0,
    };
  }

  /**
   * The deployment the current stamps were made against, and where its backlog
   * ends.
   *
   * READ-ONLY. An absent row reads as an absent deployment, which is what a
   * machine that has never drained is — and every writer below seeds the row
   * before it needs one, so nothing depends on this creating it. Keeping the
   * write off the gate path matters because the gate runs on every pass while a
   * write has to take the database's write lock.
   */
  deployment(): {
    fingerprint: string | undefined;
    backlogBefore: number | undefined;
    /**
     * The capture lane's floor — the FIRST attachment to this deployment.
     *
     * Separate from `backlogBefore` because the two lanes read opposite sides of
     * a boundary, so one number cannot serve both: the structural boundary steps
     * forward on a re-attach to take the detached window in as backlog, and the
     * capture lane reading `>= that` would then skip everything the previous
     * attached period left owed.
     */
    captureFloor: number | undefined;
  } {
    const row = getRow<{
      fingerprint: string | null;
      backlogBefore: number | null;
      captureFloor: number | null;
    }>(this.fingerprintStmt);
    return {
      fingerprint: row?.fingerprint ?? undefined,
      backlogBefore: row?.backlogBefore ?? undefined,
      captureFloor: row?.captureFloor ?? undefined,
    };
  }

  /**
   * Point the ledger at a different deployment, discarding what it recorded
   * about the previous one.
   *
   * Delivery is a fact about ONE recipient: rows sent to the deployment a
   * machine has just left are undelivered as far as the new one is concerned.
   * All three in one transaction, so a crash between them cannot leave stamps
   * attributed to the wrong deployment, or a boundary that belongs to another.
   *
   * The boundary is written HERE and only here, which is what freezes it: a
   * re-attach to the SAME deployment (a key rotation) leaves the fingerprint
   * unchanged, so this never runs and the backlog does not widen back over rows
   * the live path has since delivered.
   */
  rearmFor(fingerprint: string, backlogBefore: number): void {
    this.ensureRowStmt.run();
    withTransaction(
      this.db,
      () => {
        this.rearmStmt.run();
        this.setFingerprintStmt.run({ fingerprint, backlogBefore });
      },
      'IMMEDIATE',
    );
  }

  /**
   * End the attached period: hand its rows to the live path, and release the
   * boundary so the next attachment can freeze a new one.
   *
   * WITHOUT THIS, a detach and a re-attach to the same deployment leave a window
   * nothing delivers. The fingerprint is unchanged, so the boundary is never
   * re-frozen and stays at the FIRST attachment — while nothing forwards at all
   * during the detached period, because the machine is not attached. Rows
   * recorded in that window sit after the boundary and before the re-attach, so
   * neither path takes them, and the pending count reports none outstanding.
   *
   * Stamping the attached window is not a claim that every one of those rows
   * reached the deployment — the live path drops on failure and says so
   * elsewhere. It records that they were ITS to deliver, which is exactly the
   * status quo: they sit outside the frozen boundary today and are equally never
   * re-sent. Making it explicit is what lets the boundary move.
   *
   * ONE TRANSACTION, so a crash cannot release the boundary while leaving the
   * window unstamped — that half-state would re-send the whole attached period
   * on the next attach, which is the failure the boundary exists to prevent.
   */
  closeAttachedWindow(attachedAtMs: number, atMs: number): void {
    this.ensureRowStmt.run();
    withTransaction(
      this.db,
      () => {
        // MEASURED FROM THE BOUNDARY, not from the attachment's own timestamp.
        // `attachedAt` is re-stamped on every attach, a key rotation included,
        // while the boundary deliberately is not — that asymmetry is what keeps
        // a rotation from widening the backlog. Measuring from `attachedAt`
        // after one rotation would stamp only from the rotation onwards and
        // leave the first attached period unstamped, so the next re-attach would
        // freeze past it and the drain would re-send rows the live path owned.
        // The boundary IS where the live path's period begins, across any number
        // of rotations.
        //
        // The fallback covers a boundary that was never frozen — consent
        // declined, or no pass has run — where the attachment's own timestamp is
        // the only mark on file. It is imprecise in one narrow case: if a
        // rotation happened before any boundary was frozen, the first attached
        // period is not represented anywhere on disk and cannot be excluded.
        const row = getRow<{ backlogBefore: number | null }>(this.fingerprintStmt);
        const from = row?.backlogBefore ?? attachedAtMs;
        this.closeWindowStmt.run({ at: atMs, attachedAt: from });
        this.releaseBoundaryStmt.run();
      },
      'IMMEDIATE',
    );
  }

  /**
   * Freeze a boundary for the deployment already on file, KEEPING the stamps.
   *
   * The re-attach half of the above. Distinct from `rearmFor`, which is for a
   * different deployment and therefore discards what was delivered to the old
   * one: here the recipient is the same, so everything already sent to it stays
   * sent.
   */
  freezeBoundary(backlogBefore: number): void {
    this.ensureRowStmt.run();
    this.freezeBoundaryStmt.run({ backlogBefore });
  }

  /** Take the claim, or report that someone live already holds it. */
  claim(pid: number, host: string, nowMs: number, staleAfterMs: number): boolean {
    this.ensureRowStmt.run();
    let taken = false;
    withTransaction(
      this.db,
      () => {
        const result = this.claimStmt.run({
          pid,
          host,
          now: nowMs,
          staleBefore: nowMs - staleAfterMs,
        });
        taken = result.changes === 1;
      },
      'IMMEDIATE',
    );
    return taken;
  }

  /** Say the holder is still alive. A no-op once the claim has moved on. */
  heartbeat(pid: number, nowMs: number): void {
    this.heartbeatStmt.run({ now: nowMs, pid });
  }

  /** Give the claim up. Scoped to this holder, so a taken-over claim is left be. */
  release(pid: number): void {
    this.releaseStmt.run({ pid });
  }

  /** Who holds the claim, if anyone. Read-only, for the same reason as above. */
  lease(): HistorySyncLease | undefined {
    return getRow<HistorySyncLease>(this.leaseStmt);
  }
}
