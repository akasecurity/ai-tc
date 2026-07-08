import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionFindingInput } from '@akasecurity/schema';
import { toInspectionFindingRow } from '@akasecurity/schema';

/**
 * Inspection finding (a hit of a definition against an audit event) writer. The
 * row references its audit event, its inspection definition version, and
 * optionally a classified-data class. Caller resolves those FKs first.
 */
export class SqliteInspectionFindingsRepository {
  private readonly insertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // ON CONFLICT(id) DO NOTHING: config-scan mints a random id per fresh scan
    // (never conflicts), but the transcript reconciler mints a CONTENT-ADDRESSED
    // id (`inspectionFindingId`) so a re-read of the same hit no-ops instead of
    // conflicting and tearing down the whole reconcile transaction. Scoped to the
    // PK conflict on purpose — unlike a blanket `INSERT OR IGNORE`, a genuine
    // constraint bug (FK miss / NOT NULL / CHECK) still throws instead of being
    // silently swallowed.
    this.insertStmt = db.prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, classified_data_id,
          span_start, span_end, masked_match, action_taken, confidence)
       VALUES
         (:id, :auditEventId, :inspectionDefinitionId, :classifiedDataId,
          :spanStart, :spanEnd, :maskedMatch, :actionTaken, :confidence)
       ON CONFLICT(id) DO NOTHING`,
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
