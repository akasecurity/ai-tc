import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionDefinitionInput } from '@akasecurity/schema';
import { toInspectionDefinitionRow } from '@akasecurity/schema';

import { inspectionDefinitionId } from '../ids.ts';

/**
 * Inspection definition (a detection rule version) writer. id = sha256(tenant +
 * rule_id + version), so editing a rule mints a new row and historical findings
 * keep citing the exact version that fired. Idempotent upsert: re-loading the
 * same rule version no-ops.
 */
export class SqliteInspectionDefinitionsRepository {
  private readonly insertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT OR IGNORE INTO inspection_definitions
         (id, rule_id, name, category, severity, definition, version)
       VALUES
         (:id, :ruleId, :name, :category, :severity, :definition, :version)`,
    );
  }

  // Idempotent upsert; returns the content-addressed definition id.
  upsert(input: InspectionDefinitionInput): string {
    const id = inspectionDefinitionId(input.ruleId, input.version);
    const row = toInspectionDefinitionRow(input, id);
    this.insertStmt.run({
      id: row.id,
      ruleId: row.ruleId,
      name: row.name,
      category: row.category,
      severity: row.severity,
      definition: row.definition,
      version: row.version,
    });
    return id;
  }
}
