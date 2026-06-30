import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionFindingInput } from '@aka/schema';
import { toInspectionFindingRow } from '@aka/schema';

/**
 * Inspection finding (a hit of a definition against an audit event) writer. The
 * row references its audit event, its inspection definition version, and
 * optionally a classified-data class. Caller resolves those FKs first.
 */
export class SqliteInspectionFindingsRepository {
  private readonly insertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, classified_data_id,
          span_start, span_end, masked_match, action_taken, confidence)
       VALUES
         (:id, :auditEventId, :inspectionDefinitionId, :classifiedDataId,
          :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence)`,
    );
  }

  insertFinding(input: InspectionFindingInput): void {
    const row = toInspectionFindingRow(input);
    this.insertStmt.run({
      id: row.id,
      auditEventId: row.auditEventId,
      inspectionDefinitionId: row.inspectionDefinitionId,
      classifiedDataId: row.classifiedDataId ?? null,
      spanStart: row.spanStart,
      spanEnd: row.spanEnd,
      maskedMatch: row.maskedMatch,
      actionTaken: row.actionTaken,
      confidence: row.confidence,
    });
  }
}
