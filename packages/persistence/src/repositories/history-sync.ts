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

/** `synced_at` values that are not a delivery time. */
const SKIPPED = -1;

/** How many structural rows are delivered, waiting, or permanently skipped. */
export interface HistorySyncCounts {
  pending: number;
  sent: number;
  skipped: number;
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

    this.stampStmt = db.prepare(`UPDATE audit_events SET synced_at = :at WHERE id = :id`);

    this.countsStmt = db.prepare(
      `SELECT
         SUM(CASE WHEN synced_at IS NULL AND started_at < :before THEN 1 ELSE 0 END) AS pending,
         SUM(CASE WHEN synced_at > 0 THEN 1 ELSE 0 END) AS sent,
         SUM(CASE WHEN synced_at = ${String(SKIPPED)} THEN 1 ELSE 0 END) AS skipped
       FROM audit_events
       WHERE event_type IN (${TYPE_LIST})`,
    );

    this.fingerprintStmt = db.prepare(
      `SELECT endpoint_fingerprint AS fingerprint, backlog_before AS backlogBefore
         FROM history_sync WHERE id = 1`,
    );
    this.setFingerprintStmt = db.prepare(
      `UPDATE history_sync
          SET endpoint_fingerprint = :fingerprint, backlog_before = :backlogBefore
        WHERE id = 1`,
    );
    // Permanent skips are NOT re-armed: a row that failed to rebuild locally
    // fails the same way against any deployment.
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

  /** The deployment the current stamps were made against, and where its backlog ends. */
  deployment(): { fingerprint: string | undefined; backlogBefore: number | undefined } {
    this.ensureRowStmt.run();
    const row = getRow<{ fingerprint: string | null; backlogBefore: number | null }>(
      this.fingerprintStmt,
    );
    return {
      fingerprint: row?.fingerprint ?? undefined,
      backlogBefore: row?.backlogBefore ?? undefined,
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

  lease(): HistorySyncLease | undefined {
    this.ensureRowStmt.run();
    return getRow<HistorySyncLease>(this.leaseStmt);
  }
}
