import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionDefinitionInput, LocalIdentity } from '@aka/schema';
import { toInspectionDefinitionRow } from '@aka/schema';

import { inspectionDefinitionId } from '../ids.ts';

/**
 * Inspection definition (a detection rule version) writer. id = sha256(tenant +
 * rule_id + version), so editing a rule mints a new row and historical findings
 * keep citing the exact version that fired. Idempotent upsert: re-loading the
 * same rule version no-ops.
 */
export class SqliteInspectionDefinitionsRepository {
  private readonly insertStmt: StatementSync;

  constructor(
    private readonly db: DatabaseSync,
    private readonly identity: LocalIdentity,
  ) {
    this.insertStmt = db.prepare(
      `INSERT OR IGNORE INTO inspection_definitions
         (id, tenant_id, rule_id, name, category, severity, definition, version)
       VALUES
         (:id, :tenantId, :ruleId, :name, :category, :severity, :definition, :version)`,
    );
  }

  // Idempotent upsert; returns the content-addressed definition id.
  upsert(input: InspectionDefinitionInput): string {
    const id = inspectionDefinitionId(this.identity.tenantId, input.ruleId, input.version);
    const row = toInspectionDefinitionRow(input, id, this.identity.tenantId);
    this.insertStmt.run({
      id: row.id,
      tenantId: row.tenantId,
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
