import type { DatabaseSync } from 'node:sqlite';

import { withTransaction } from './internal/transactions.ts';

/**
 * True when any of the three sample-seeded domains still has legacy rows.
 * Lets purgeSampleData bail out before opening a write transaction — the
 * common case, going forward, is a store that never held sample data, and
 * that path should stay read-only (no app_meta creation, no lock).
 */
function hasLegacySampleRows(db: DatabaseSync): boolean {
  const row = db
    .prepare(
      `SELECT (
         EXISTS(SELECT 1 FROM share_destination WHERE provenance = 'sample')
         OR EXISTS(SELECT 1 FROM audit_events WHERE id LIKE 'sample:activity:%')
         OR EXISTS(SELECT 1 FROM inventory_asset WHERE provenance = 'sample')
       ) AS n`,
    )
    .get() as { n: number };
  return Boolean(row.n);
}

/**
 * One-shot cleanup of the RETIRED demo/sample dataset. The product no longer
 * seeds sample data anywhere (removed by product decision), but stores created
 * by previously shipped builds still hold rows tagged provenance='sample' /
 * id-prefixed `sample:` — this deletes exactly those, leaving real
 * scanned/ingested rows untouched. Invoked by the web-ui bootstrap once per
 * process; a store with no legacy rows exits on the read-only guard above
 * without opening a transaction.
 * Fail-open: demo-row cleanup must never break the app.
 */
export function purgeSampleData(db: DatabaseSync): void {
  try {
    if (!hasLegacySampleRows(db)) return;

    withTransaction(db, () => {
      // Data Shares (children first).
      db.exec(
        `DELETE FROM share_call_site WHERE endpoint_id IN (
           SELECT e.id FROM share_endpoint e
           JOIN share_destination d ON d.id = e.destination_id
           WHERE d.provenance = 'sample')`,
      );
      db.exec(
        `DELETE FROM egress_decision_override WHERE destination_id IN (
           SELECT id FROM share_destination WHERE provenance = 'sample')`,
      );
      db.exec(
        `DELETE FROM share_endpoint WHERE destination_id IN (
           SELECT id FROM share_destination WHERE provenance = 'sample')`,
      );
      db.exec("DELETE FROM share_destination WHERE provenance = 'sample'");

      // Inventory (children first, then the sample roots in the shared tables).
      db.exec(
        `DELETE FROM harness_asset WHERE asset_id IN (SELECT id FROM inventory_asset WHERE provenance = 'sample')
            OR harness_id IN (SELECT id FROM inventory WHERE object_type = 'harness' AND json_extract(attributes, '$.provenance') = 'sample')`,
      );
      db.exec(
        `DELETE FROM mcp_trust_override WHERE asset_id IN (SELECT id FROM inventory_asset WHERE provenance = 'sample')`,
      );
      db.exec(
        `DELETE FROM file_access_override WHERE project_id IN (SELECT id FROM source_project WHERE json_extract(attributes, '$.provenance') = 'sample')`,
      );
      db.exec(
        `DELETE FROM project_file WHERE project_id IN (SELECT id FROM source_project WHERE json_extract(attributes, '$.provenance') = 'sample')`,
      );
      db.exec("DELETE FROM inventory_asset WHERE provenance = 'sample'");
      db.exec(
        `DELETE FROM source_project WHERE json_extract(attributes, '$.provenance') = 'sample'`,
      );
      db.exec(
        `DELETE FROM inventory WHERE object_type = 'harness' AND json_extract(attributes, '$.provenance') = 'sample'`,
      );

      // Activity (descendants before roots — the self-referential FK forbids
      // deleting a root while its timeline rows still point at it).
      db.exec("DELETE FROM inspection_findings WHERE id LIKE 'sample:activity:%'");
      db.exec("DELETE FROM inspection_definitions WHERE id LIKE 'sample:activity:%'");
      db.exec("DELETE FROM audit_events WHERE root_session_id LIKE 'sample:activity:%'");
      db.exec("DELETE FROM audit_events WHERE id LIKE 'sample:activity:%'");

      // The retired seeder's app_meta markers (`sample_seeded:*`). The table is
      // plugin-local and may not exist on stores the seeder never touched.
      db.exec(`CREATE TABLE IF NOT EXISTS app_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )`);
      db.exec("DELETE FROM app_meta WHERE key LIKE 'sample_seeded:%'");
    });
  } catch {
    // Fail-open: a locked/corrupt DB leaves the store untouched.
  }
}
