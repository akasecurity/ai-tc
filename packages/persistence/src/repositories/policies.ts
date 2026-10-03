import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { ActionTaken, DetectionCategory, Policy as PolicyType } from '@akasecurity/schema';
import { DEFAULT_ACTIONS, Policy } from '@akasecurity/schema';

import { allRows, countScalar, intToBool, mapRowsTolerant } from '../internal/rows.ts';
import { failOpenTransaction } from '../internal/transactions.ts';
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
 * one store per machine.
 */
export class SqlitePoliciesRepository implements PoliciesReadPort {
  constructor(private readonly db: DatabaseSync) {}

  readPolicies(): Promise<PolicyType[]> {
    const rows = allRows<PolicyRow>(this.db.prepare('SELECT * FROM policies'));
    const policies = mapRowsTolerant(rows, (row) => {
      // JSON columns re-enter as unknown and are validated by Policy.parse.
      const target: unknown = JSON.parse(row.target);
      const customKeywords: unknown = row.custom_keywords
        ? JSON.parse(row.custom_keywords)
        : undefined;
      return Policy.parse({
        id: row.id,
        scope: row.scope,
        target,
        action: row.action,
        enabled: intToBool(row.enabled),
        customKeywords,
      });
    });
    return Promise.resolve(policies);
  }

  // Seed one policy per bundled category at Monitor so the detection-type config
  // exists from first run. An unassigned pack's rules follow these rows, so
  // Monitor here is the posture of every pack that ships no defaultPolicy; a pack
  // that ships one carries its own assignment instead. Only when the
  // table is empty, so a user's edits are never clobbered.
  seedDefaults(): void {
    const count = countScalar(this.db, 'SELECT count(*) AS n FROM policies');
    if (count > 0) {
      this.monitorUntouchedSeeds();
      return;
    }
    const stmt = this.db.prepare(
      `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
       VALUES (:id, 'global', :target, :action, 1, :now, :now)`,
    );
    failOpenTransaction(this.db, () => {
      for (const category of Object.keys(DEFAULT_ACTIONS)) {
        stmt.run({
          id: randomUUID(),
          target: JSON.stringify({ category }),
          action: 'log',
          now: Date.now(),
        });
      }
    });
  }

  // Stores seeded by an earlier build hold DEFAULT_ACTIONS in their category
  // rows. Those rows used to be shadowed by the Monitor every unassigned pack
  // emitted; now that unassigned packs defer to them, an untouched one would
  // turn Monitor into Warn on upgrade with nobody having asked. So a row still
  // exactly as seeded — the seeded action, never updated since it was created —
  // is moved to Monitor. A row the user, the setup wizard or the warn-era cap
  // ever wrote has a later updated_at and is left alone. updated_at is NOT
  // advanced, so a moved row still reads as an untouched seed (see
  // isCategoryChosen); it never matches again because it is no longer off 'log'.
  private monitorUntouchedSeeds(): void {
    // A read first, so the steady state (nothing left to move) takes no write
    // lock on a path every hook opens.
    const untouched = allRows<{ category: string; action: string }>(
      this.db.prepare(
        `SELECT json_extract(target, '$.category') AS category, action FROM policies
          WHERE scope = 'global' AND json_extract(target, '$.category') IS NOT NULL
            AND action <> 'log' AND updated_at = created_at`,
      ),
    ).filter(
      (row) => (DEFAULT_ACTIONS as Partial<Record<string, string>>)[row.category] === row.action,
    );
    if (untouched.length === 0) return;
    const stmt = this.db.prepare(
      `UPDATE policies SET action = 'log'
        WHERE scope = 'global' AND json_extract(target, '$.category') = :category
          AND action = :seeded AND action <> 'log' AND updated_at = created_at`,
    );
    failOpenTransaction(this.db, () => {
      for (const row of untouched) {
        stmt.run({ category: row.category, seeded: row.action });
      }
    });
  }

  // Insert-or-update the single global per-category policy row, keyed on the
  // existing uq_policies_scope_target unique index (scope, target). `action`
  // uses the SAME vocabulary seedDefaults writes (DEFAULT_ACTIONS' ActionTaken
  // values), so the runtime's resolveAction reads rows written by either path
  // identically. On conflict, `action`, `enabled`, and `updated_at` are updated;
  // `id` and `created_at` are left exactly as they were. Either way updated_at
  // ends up later than created_at, which is what marks the row as chosen.
  upsertCategoryAction(category: DetectionCategory, action: ActionTaken): void {
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO policies (id, scope, target, action, enabled, created_at, updated_at)
         VALUES (:id, 'global', :target, :action, 1, :now, :now + 1)
         ON CONFLICT(scope, target) DO UPDATE SET action = excluded.action, enabled = 1,
           updated_at = MAX(excluded.updated_at, policies.created_at + 1)`,
      )
      .run({ id: randomUUID(), target: JSON.stringify({ category }), action, now });
  }

  // Caps every global per-category policy currently set to block/redact down
  // to warn (see warn-era-cap.ts). Rule-targeted policies are untouched.
  // Returns the number of rows changed.
  capCategoryActions(): number {
    const info = this.db
      .prepare(
        `UPDATE policies SET action='warn', updated_at=:now
         WHERE scope='global' AND action IN ('block','redact')
           AND json_extract(target,'$.category') IS NOT NULL`,
      )
      .run({ now: Date.now() });
    return Number(info.changes);
  }

  // Whether the category's row was ever written after it was created — by the
  // user, the setup wizard or a cap. A row still as seeded (updated_at equal to
  // created_at) is not a choice, so a posture filling gaps may replace it.
  isCategoryChosen(category: DetectionCategory): boolean {
    const row = this.db
      .prepare(
        `SELECT created_at AS c, updated_at AS u FROM policies
          WHERE scope='global' AND json_extract(target,'$.category') = :category`,
      )
      .get({ category }) as { c: number; u: number } | undefined;
    return row !== undefined && row.u !== row.c;
  }

  // Read the current action for a single global per-category policy row, mirroring
  // upsertCategoryAction's category-lookup predicate. Returns undefined when no
  // row exists yet, so callers can distinguish an unset category from a set one.
  getCategoryAction(category: DetectionCategory): ActionTaken | undefined {
    const row = this.db
      .prepare(
        `SELECT action FROM policies WHERE scope='global' AND json_extract(target,'$.category') = :category`,
      )
      .get({ category }) as { action: ActionTaken } | undefined;
    return row?.action;
  }
}
