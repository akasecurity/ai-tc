import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { InventoryInput, InventoryObjectType } from '@akasecurity/schema';
import { toInventoryRow } from '@akasecurity/schema';

import { inventoryId } from '../ids.ts';

/**
 * Inventory (existence) dimension writer/reader, bound to one open DB + local
 * identity. Upserts are idempotent on the content-addressed id; the descriptive
 * attributes are Type-1 (overwrite to latest) on a repeat upsert while
 * `first_seen` is pinned to the first sighting. So the "small dimension"
 * stays small and reflects the current os_version / harness_version, and any
 * point-in-time value is preserved by snapshotting onto the audit fact instead.
 * Facets read this table (with the generated-column indexes) — the audit fact
 * table is never scanned for DISTINCT.
 */
export class SqliteInventoryRepository {
  private readonly upsertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    // ON CONFLICT overwrites the mutable columns to latest and bumps last_seen,
    // but leaves first_seen untouched (it is absent from the SET list).
    // Contract: `attributes` is Type-1 (replace, not merge) — `excluded.attributes`
    // overwrites the stored bag wholesale, so callers MUST send a COMPLETE bag on
    // every upsert. A partial bag (missing os_version) would null the generated
    // facet column. `resolveInventoryContext` always sends a full `node:os` bag, so
    // this holds today; a future partial caller must merge client-side (or this
    // upsert must switch to json_patch on the stored JSON) to avoid erasing facets.
    this.upsertStmt = db.prepare(
      `INSERT INTO inventory
         (id, object_type, location, title, host_id, attributes, first_seen, last_seen)
       VALUES
         (:id, :objectType, :location, :title, :hostId, :attributes, :firstSeen, :lastSeen)
       ON CONFLICT(id) DO UPDATE SET
         location = excluded.location,
         title = excluded.title,
         host_id = excluded.host_id,
         attributes = excluded.attributes,
         last_seen = excluded.last_seen`,
    );
  }

  // Idempotent content-addressed upsert; returns the resolved inventory id.
  upsert(input: InventoryInput, now: number = Date.now()): string {
    const id = inventoryId(input.objectType, input.identityKey);
    const row = toInventoryRow(input, id, now);
    this.upsertStmt.run({
      id: row.id,
      objectType: row.objectType,
      location: row.location ?? null,
      title: row.title ?? null,
      hostId: row.hostId ?? null,
      attributes: row.attributes,
      firstSeen: row.firstSeen,
      lastSeen: row.lastSeen,
    });
    return id;
  }

  // The full row, for round-trip assertions.
  findById(id: string): InventoryRow | undefined {
    const row = this.db.prepare('SELECT * FROM inventory WHERE id = :id').get({ id }) as
      InventoryRow | undefined;
    return row;
  }

  // Distinct titles for an object_type — a filter facet (e.g. hostnames),
  // served from the object_type index, never from audit_events.
  distinctTitles(objectType: InventoryObjectType): string[] {
    const rows = this.db
      .prepare(
        `SELECT DISTINCT title FROM inventory
         WHERE object_type = :objectType AND title IS NOT NULL
         ORDER BY title`,
      )
      .all({ objectType }) as unknown as { title: string }[];
    return rows.map((r) => r.title);
  }

  // Distinct host os_version values — a facet served from an inventory index
  // over the generated column, never from the audit fact (confirm via EXPLAIN
  // QUERY PLAN).
  osVersions(): string[] {
    const rows = this.db
      .prepare(
        `SELECT DISTINCT os_version AS value FROM inventory
         WHERE object_type = 'host' AND os_version IS NOT NULL
         ORDER BY value`,
      )
      .all() as unknown as { value: string }[];
    return rows.map((r) => r.value);
  }
}

// The persisted shape (snake_case columns), for read assertions.
interface InventoryRow {
  id: string;
  object_type: string;
  location: string | null;
  title: string | null;
  host_id: string | null;
  attributes: string;
  os_version: string | null;
  harness_version: string | null;
  first_seen: number;
  last_seen: number;
}
