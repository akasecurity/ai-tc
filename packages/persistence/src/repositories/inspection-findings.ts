import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionFindingInput } from '@akasecurity/schema';
import { toInspectionFindingRow } from '@akasecurity/schema';

import { bindParams } from '../internal/rows.ts';

/**
 * Inspection finding (a hit of a definition against an audit event) writer. The
 * row references its audit event, its inspection definition version, and
 * optionally a classified-data class. Caller resolves those FKs first.
 */
export class SqliteInspectionFindingsRepository {
  private readonly insertStmt: StatementSync;

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
