import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionFindingInput } from '@akasecurity/schema';
import { CAPTURE_EVENT_TYPES_SQL, toInspectionFindingRow } from '@akasecurity/schema';

import { bindParams } from '../internal/rows.ts';

/**
 * Inspection finding (a hit of a definition against an audit event) writer. The
 * row references its audit event, its inspection definition version, and
 * optionally a classified-data class. Caller resolves those FKs first.
 */
export class SqliteInspectionFindingsRepository {
  private readonly insertStmt: StatementSync;
  private readonly sessionDupStmt: StatementSync;
  private readonly eventDupStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // TWO conflict targets on one statement, chained — SQLite (3.35+; this
    // package runs on node:sqlite's bundled 3.5x) tries each ON CONFLICT clause
    // in the order written and applies the first whose target the row actually
    // violated, so this is NOT "pick one and drop the other": both constraints
    // stay live and each gets its own, independently correct, reconciliation.
    //
    // 1) ON CONFLICT(id) DO UPDATE SET inspection_definition_id = excluded.…:
    // config-scan mints a random id per fresh scan (never conflicts), but the
    // transcript reconciler mints a CONTENT-ADDRESSED id (`inspectionFindingId`,
    // keyed on the RULE id rather than the definition id) so a re-read of the same
    // hit conflicts on re-detection instead of tearing down the whole reconcile
    // transaction. The conflict refreshes `inspection_definition_id` to whatever
    // definition fired THIS time: without that, a finding re-detected under a
    // bumped rule version would keep pointing at the stale definition row, and its
    // stored severity/category would never track a pack update.
    //
    // 2) ON CONFLICT (finding_key) DO UPDATE SET …: the live capture path
    // (recordCapture) mints a plain random `id` per detection — like the legacy
    // `findings` table did — so re-detecting the SAME at-rest finding produces a
    // FRESH id every time; nothing would ever hit clause 1. `finding_key` is what
    // correlates those repeat detections onto one row (uq_inspection_findings_key;
    // NULL never equals NULL in a unique index, so in-flight findings with no key
    // always insert fresh, exactly like SqliteFindingsRepository's mirror-image
    // ON CONFLICT (finding_key)). Refreshes every mutable column EXCEPT
    // `finding_key` itself (baked into the conflict target, so a conflict can
    // never carry a different one — same reasoning as the legacy writer) and
    // `first_detected_at`, which is DELIBERATELY excluded so a re-detection keeps
    // the ORIGINAL detection time (see the VALUES clause below).
    //
    // Neither clause is a blanket `INSERT OR IGNORE`: a genuine constraint bug
    // (FK miss / NOT NULL / CHECK) still throws instead of being silently
    // swallowed by either.
    this.insertStmt = db.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, classified_data_id,
          span_start, span_end, masked_match, action_taken, confidence,
          finding_key, first_detected_at)
       VALUES
         (:id, :auditEventId, :inspectionDefinitionId, :classifiedDataId,
          :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence,
          :findingKey,
          COALESCE(:firstDetectedAt, (SELECT started_at FROM audit_events WHERE id = :auditEventId)))
       ON CONFLICT(id) DO UPDATE SET
         inspection_definition_id = excluded.inspection_definition_id
       ON CONFLICT (finding_key) DO UPDATE SET
         audit_event_id = excluded.audit_event_id,
         inspection_definition_id = excluded.inspection_definition_id,
         classified_data_id = excluded.classified_data_id,
         span_start = excluded.span_start,
         span_end = excluded.span_end,
         masked_match = excluded.masked_match,
         action_taken = excluded.action_taken,
         confidence = excluded.confidence`,
    );

    // Has this (rule, masked value) already been recorded somewhere in this
    // session? Mirrors the legacy `SqliteFindingsRepository.sessionDupStmt`
    // (which joined findings ⋈ events on `json_extract(e.metadata,
    // '$.sessionId')`), rejoined onto the generalized trio now that rule_id
    // lives on inspection_definitions rather than on the finding row itself,
    // and the session id is audit_events' own `root_session_id` column
    // instead of a metadata blob. Used to suppress a value that crosses
    // several surfaces within one action (prompt → tool call) — see
    // recordCapture's session-dedup call site.
    //
    // The `event_type IN (…)` guard is load-bearing: unlike the legacy
    // `events` table (which held only capture kinds), audit_events also holds
    // the transcript reconciler's `tool_call`/`llm_call` rows, which carry the
    // same `root_session_id`. Without the guard a reconciler finding would
    // dedup-suppress a later same-session capture, and the surviving tool_call
    // row is excluded by every capture-kind read — so the finding would vanish.
    this.sessionDupStmt = db.prepare(
      `SELECT 1 FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
        WHERE d.rule_id = :ruleId AND f.masked_match = :maskedMatch
          AND e.root_session_id = :sessionId
          AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
        LIMIT 1`,
    );

    // Has this exact (rule, masked value, span) already been recorded against
    // THIS audit event? An in-flight finding (prompt/response/tool_use) mints
    // a fresh random `id` and carries no `finding_key` (nothing to re-scan
    // against), so neither of insertStmt's ON CONFLICT clauses ever fires for
    // it — unlike a content-addressed audit event (captureId(sessionId,
    // contentHash)), which resolves an exact resubmission onto the SAME row
    // via INSERT OR IGNORE, a resubmitted in-flight finding would otherwise
    // duplicate on every replay of the identical capture. This check restores
    // that idempotency at the finding level: scoped to one audit event (never
    // across two different events, which is exactly what finding_key
    // reconciliation is for), and keyed on span too, so two genuinely
    // distinct hits of the same value within one capture (e.g. a secret
    // pasted twice in one prompt) are still both kept.
    this.eventDupStmt = db.prepare(
      `SELECT 1 FROM inspection_findings f
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
        WHERE f.audit_event_id = :auditEventId AND d.rule_id = :ruleId
          AND f.masked_match = :maskedMatch
          AND f.span_start = :spanStart AND f.span_end = :spanEnd
        LIMIT 1`,
    );
  }

  // True when an earlier event in the same session already recorded a finding
  // with the same rule and masked value. The current event's own findings are
  // inserted one at a time in caller order, so an earlier finding in the SAME
  // recordCapture call is visible to a later duplicate check within it too.
  isSessionDuplicate(ruleId: string, maskedMatch: string, sessionId: string): boolean {
    return this.sessionDupStmt.get({ ruleId, maskedMatch, sessionId }) !== undefined;
  }

  // True when this exact detection (rule + masked value + span) is already
  // recorded against the given audit event.
  isEventDuplicate(
    auditEventId: string,
    ruleId: string,
    maskedMatch: string,
    spanStart: number,
    spanEnd: number,
  ): boolean {
    return (
      this.eventDupStmt.get({ auditEventId, ruleId, maskedMatch, spanStart, spanEnd }) !== undefined
    );
  }

  insertFinding(input: InspectionFindingInput): void {
    const row = toInspectionFindingRow(input);
    this.insertStmt.run(
      bindParams({
        id: row.id,
        auditEventId: row.auditEventId,
        inspectionDefinitionId: row.inspectionDefinitionId,
        classifiedDataId: row.classifiedDataId,
        spanStart: row.spanStart,
        spanEnd: row.spanEnd,
        maskedMatch: row.maskedMatch,
        actionTaken: row.actionTaken,
        confidence: row.confidence,
        findingKey: row.findingKey,
        firstDetectedAt: row.firstDetectedAt,
      }),
    );
  }
}
