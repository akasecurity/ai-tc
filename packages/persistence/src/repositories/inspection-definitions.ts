import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InspectionDefinitionInput } from '@akasecurity/schema';
import { toInspectionDefinitionRow } from '@akasecurity/schema';

import { inspectionDefinitionId } from '../ids.ts';

/**
 * Inspection definition (a detection rule version) writer.
 *
 * `id = sha256Hex(canonicalIdentity(['inspection_definition', rule_id, version]))`
 * — see `inspectionDefinitionId` in ../ids.ts. `canonicalIdentity` JSON-encodes
 * the parts as an array rather than joining them, which is what keeps the part
 * boundaries: concatenation would put rule `ab` version `c` and rule `a` version
 * `bc` on one digest, collapsing two rule versions onto a single row so
 * historical findings cite the wrong definition. Content-addressed on the rule's
 * identity and its version and nothing else, so editing a rule mints a NEW row
 * and historical findings keep citing the exact version that fired. Two stores
 * that load the same rule version derive the same id.
 *
 * Idempotent upsert: re-loading the same rule version no-ops.
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
