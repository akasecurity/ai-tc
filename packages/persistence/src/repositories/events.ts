import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { IngestEvent } from '@akasecurity/schema';
import { CAPTURE_EVENT_TYPES_SQL, toEventRow } from '@akasecurity/schema';

import { allRows, bindParams } from '../internal/rows.ts';
import type { EventsReadPort } from '../ports.ts';

/**
 * Events table writer/reader, bound to one open DB. The insert is a single
 * statement (the atomic event+findings write is composed by the LocalDatabase
 * facade inside one transaction). The local store is single-tenant, so there
 * is no tenant predicate on any query.
 */
export class SqliteEventsRepository implements EventsReadPort {
  private readonly insertStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.insertStmt = db.prepare(
      `INSERT INTO events (id, source_tool, kind, occurred_at, content_hash, content, metadata)
       VALUES (:id, :sourceTool, :kind, :occurredAt, :contentHash, :content, :metadata)`,
    );
  }

  insertEvent(event: IngestEvent): void {
    const row = toEventRow(event);
    this.insertStmt.run(
      bindParams({
        id: row.id,
        sourceTool: row.sourceTool,
        kind: row.kind,
        occurredAt: row.occurredAt,
        contentHash: row.contentHash,
        content: row.content,
        metadata: row.metadata,
      }),
    );
  }

  // Every recorded capture's content hash — the historical backfill loads this
  // once to skip transcript messages it has already stored, so re-running the
  // scan never duplicates findings.
  // Async (Promise.resolve over synchronous node:sqlite) so it satisfies the
  // async EventsReadPort contract.
  //
  // audit_events also holds structural rows (session, run, tool_call, llm_call,
  // source_lookup, config_scan) with a NULL content_hash, so the capture-kind
  // predicate isn't load-bearing here — it documents intent and keeps the scan
  // index-friendly rather than walking rows that can never match.
  contentHashes(): Promise<Set<string>> {
    const rows = allRows<{ content_hash: string }>(
      this.db.prepare(
        `SELECT content_hash FROM audit_events
         WHERE event_type IN (${CAPTURE_EVENT_TYPES_SQL})`,
      ),
    );
    return Promise.resolve(new Set(rows.map((r) => r.content_hash)));
  }
}
