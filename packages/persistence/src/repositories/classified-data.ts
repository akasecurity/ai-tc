import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { ClassifiedDataInput } from '@akasecurity/schema';
import { toClassifiedDataRow } from '@akasecurity/schema';

import { classifiedDataId } from '../ids.ts';

/**
 * Classified data (a small CLASS dimension keyed by class only — `aws_key`,
 * `email_pii`, …). A handful of rows referenced by inspection findings.
 * Per-occurrence detail (span, masked match, action) lives on the finding, never
 * here, and the id is never a hash of secret content.
 */
export class SqliteClassifiedDataRepository {
  private readonly insertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT OR IGNORE INTO classified_data (id, class, label, attributes)
       VALUES (:id, :class, :label, :attributes)`,
    );
  }

  // Idempotent upsert; returns the content-addressed class id.
  upsert(input: ClassifiedDataInput): string {
    const id = classifiedDataId(input.class);
    const row = toClassifiedDataRow(input, id);
    this.insertStmt.run({
      id: row.id,
      class: row.class,
      label: row.label ?? null,
      attributes: row.attributes ?? null,
    });
    return id;
  }
}
