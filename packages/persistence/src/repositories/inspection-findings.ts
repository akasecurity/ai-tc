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
    // ON CONFLICT(id) DO UPDATE SET inspection_definition_id = excluded.…:
    // config-scan mints a random id per fresh scan (never conflicts), but the
    // transcript reconciler mints a CONTENT-ADDRESSED id (`inspectionFindingId`,
    // keyed on the RULE id rather than the definition id) so a re-read of the same
    // hit conflicts on re-detection instead of tearing down the whole reconcile
    // transaction. The conflict refreshes `inspection_definition_id` to whatever
    // definition fired THIS time: without that, a finding re-detected under a
    // bumped rule version would keep pointing at the stale definition row, and its
    // stored severity/category would never track a pack update. Scoped to the PK
    // conflict on purpose — unlike a blanket `INSERT OR IGNORE`, a genuine
    // constraint bug (FK miss / NOT NULL / CHECK) still throws instead of being
    // silently swallowed.
    this.insertStmt = db.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, classified_data_id,
          span_start, span_end, masked_match, action_taken, confidence)
       VALUES
         (:id, :auditEventId, :inspectionDefinitionId, :classifiedDataId,
          :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence)
       ON CONFLICT(id) DO UPDATE SET inspection_definition_id = excluded.inspection_definition_id`,
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
      }),
    );
  }
}
