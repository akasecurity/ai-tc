import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { Policy as PolicyType } from '@akasecurity/schema';
import { DEFAULT_ACTIONS, Policy } from '@akasecurity/schema';

import type { PoliciesReadPort } from '../ports.ts';

interface PolicyRow {
  id: string;
  scope: string;
  target: string;
  action: string;
  enabled: number;
  custom_keywords: string | null;
}

/**
 * Policies table reader + the first-run seeder, bound to one open DB. The seeded
 * per-category defaults are what the runtime resolves enforcement actions
 * against; `/aka:config` edits them later. The local store is
 * tenant-free (single tenant).
 */
export class SqlitePoliciesRepository implements PoliciesReadPort {
  constructor(private readonly db: DatabaseSync) {}

  readPolicies(): Promise<PolicyType[]> {
    const rows = this.db.prepare('SELECT * FROM policies').all() as unknown as PolicyRow[];
    const policies: PolicyType[] = [];
    for (const row of rows) {
      try {
        // JSON columns re-enter as unknown and are validated by Policy.parse.
        const target: unknown = JSON.parse(row.target);
        const customKeywords: unknown = row.custom_keywords
          ? JSON.parse(row.custom_keywords)
          : undefined;
        policies.push(
          Policy.parse({
            id: row.id,
            scope: row.scope,
            target,
            action: row.action,
            enabled: row.enabled === 1,
            customKeywords,
          }),
        );
      } catch {
        // Skip a malformed/foreign policy row rather than failing the read.
      }
    }
    return Promise.resolve(policies);
  }

  // Seed one policy per bundled category from DEFAULT_ACTIONS so the
  // detection-type config exists from first run. Only when the table is empty,
  // so a user's edits are never clobbered.
  seedDefaults(): void {
    const count = (this.db.prepare('SELECT count(*) AS c FROM policies').get() as { c: number }).c;
    if (count > 0) return;
    const stmt = this.db.prepare(
      `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
       VALUES (:id, 'global', :target, :action, 1, :now, :now)`,
    );
    this.db.exec('BEGIN');
    try {
      for (const [category, action] of Object.entries(DEFAULT_ACTIONS)) {
        stmt.run({
          id: randomUUID(),
          target: JSON.stringify({ category }),
          action,
          now: Date.now(),
        });
      }
      this.db.exec('COMMIT');
    } catch {
      this.db.exec('ROLLBACK');
    }
  }
}
