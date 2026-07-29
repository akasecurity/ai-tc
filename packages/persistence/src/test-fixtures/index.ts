import type { DatabaseSync } from 'node:sqlite';

import { seedSampleAuditEvents } from './sample-audit-events.ts';
import { seedSampleInventory } from './sample-inventory.ts';
import { seedSampleShares } from './sample-shares.ts';

/**
 * TEST FIXTURES ONLY. The product seeds no sample/demo data (removed by product
 * decision — the web-ui purges the retired dataset from historical stores via
 * sample-purge.ts). These rich fully-shaped datasets survive purely as
 * fixtures for the repository read-surface tests; nothing outside *.test.ts may
 * import this directory, so shipped bundles never contain it.
 *
 * Unlike the retired product seeder there is no marker table and no emptiness
 * gating — tests own their stores and seed exactly once.
 */
export function seedSampleFixtures(db: DatabaseSync): void {
  // One transaction, not one per row. In autocommit each insert commits on its
  // own, and on a file-backed store every commit is a separate flush — the cost
  // the Windows CI runner charges orders of magnitude more for than a local
  // disk does, which is enough to put a seeding test near the per-test timeout.
  // A caller that already holds a transaction keeps it; this opens none of its
  // own inside one.
  if (db.isTransaction) {
    seedAll(db);
    return;
  }
  db.exec('BEGIN');
  try {
    seedAll(db);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function seedAll(db: DatabaseSync): void {
  seedSampleShares(db);
  seedSampleInventory(db);
  seedSampleAuditEvents(db);
}

export { seedSampleAuditEvents, seedSampleInventory, seedSampleShares };
