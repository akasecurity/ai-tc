import type { DatabaseSync } from 'node:sqlite';

import { allRows } from '../internal/rows.ts';
import type { EventsReadPort } from '../ports.ts';

/**
 * Content-hash reads over the generalized `audit_events` table, bound to one
 * open DB. The legacy `events` table this class once wrote directly no
 * longer exists (recordCapture writes `audit_events` via
 * SqliteAuditEventsRepository instead — see database.ts); a dropped-then-
 * viewed compatibility shape backs any already-shipped binary that still
 * writes the old table by name. The local store is single-tenant, so there
 * is no tenant predicate on any query.
 */
export class SqliteEventsRepository implements EventsReadPort {
  constructor(private readonly db: DatabaseSync) {}

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
         WHERE event_type IN ('prompt','response','code_change','tool_use')`,
      ),
    );
    return Promise.resolve(new Set(rows.map((r) => r.content_hash)));
  }
}
