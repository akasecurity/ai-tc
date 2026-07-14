import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { SourceProjectInput } from '@akasecurity/schema';
import { toSourceProjectRow } from '@akasecurity/schema';

import { sourceProjectId } from '../ids.ts';

/**
 * Source/Project (the "what code/data" axis) writer/reader. Content-addressed by
 * remote url so two machines reporting the same repo collapse to one row.
 * Idempotent upsert, same Type-1 (overwrite-to-latest, pinned first_seen)
 * semantics as the inventory dimension.
 */
export class SqliteSourceProjectRepository {
  private readonly upsertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.upsertStmt = db.prepare(
      `INSERT INTO source_project
         (id, url, name, attributes, first_seen, last_seen)
       VALUES
         (:id, :url, :name, :attributes, :firstSeen, :lastSeen)
       ON CONFLICT(id) DO UPDATE SET
         url = excluded.url,
         name = excluded.name,
         attributes = excluded.attributes,
         last_seen = excluded.last_seen`,
    );
  }

  upsert(input: SourceProjectInput, now: number = Date.now()): string {
    const id = sourceProjectId(input.url);
    const row = toSourceProjectRow(input, id, now);
    this.upsertStmt.run({
      id: row.id,
      url: row.url ?? null,
      name: row.name ?? null,
      attributes: row.attributes,
      firstSeen: row.firstSeen,
      lastSeen: row.lastSeen,
    });
    return id;
  }

  findById(id: string): SourceProjectRow | undefined {
    return this.db.prepare('SELECT * FROM source_project WHERE id = :id').get({ id }) as
      SourceProjectRow | undefined;
  }

  // Distinct project names — a filter facet, served from the source_project
  // table, never from the audit fact table.
  distinctNames(): string[] {
    const rows = this.db
      .prepare(
        `SELECT DISTINCT name FROM source_project
         WHERE name IS NOT NULL
         ORDER BY name`,
      )
      .all() as unknown as { name: string }[];
    return rows.map((r) => r.name);
  }
}

interface SourceProjectRow {
  id: string;
  url: string | null;
  name: string | null;
  attributes: string;
  first_seen: number;
  last_seen: number;
}
