import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { StoredCaptureStatus } from '@akasecurity/schema';
import {
  epochMillisToIso,
  fromCaptureStatusAttributes,
  pickReportedCaptureStatus,
  WebSourceTool,
} from '@akasecurity/schema';

import { parseJsonObject } from '../internal/json.ts';
import { allRows } from '../internal/rows.ts';

interface CaptureStatusRow {
  startedAt: number;
  attributes: string | null;
}

/**
 * How many of a site's newest rows one read looks at.
 *
 * The read reports the newest row that observed the site's turn path (see
 * `pickReportedCaptureStatus`), so it has to see past a run of watching-only
 * reports — a tab relays one when its tap patches and another when the page
 * unloads, so an untouched tab writes two. Bounded because this walks the
 * `capture_status` range: past this many watching-only reports the older
 * verdict is treated as stale and the newest row is reported instead.
 */
const STATUS_LOOKBACK_ROWS = 32;

/**
 * Read side of the browser extension's reported capture status — the durable
 * home the native host writes through `recordAuditEvent` (event_type
 * `capture_status`), so a second process (`aka extension status`) and a
 * restarted host both have somewhere to read the same answer from.
 *
 * One bounded seek per site rather than one scan of the whole range: the
 * generated `source_tool` column carries no index of its own, so a query that
 * asks for every site at once re-tests each row against the other site's
 * newest timestamp and degrades quadratically as history accumulates. This is
 * not a page read, so it is not added to `hot-read-query-plans.test.ts`.
 */
export class SqliteCaptureStatusRepository {
  private readonly recentStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.recentStmt = db.prepare(
      `SELECT a.started_at AS startedAt, a.attributes AS attributes
         FROM audit_events a
        WHERE a.event_type = 'capture_status'
          AND a.source_tool = ?
        ORDER BY a.started_at DESC, a.id DESC
        LIMIT ?`,
    );
  }

  /** The reported status per site, in registry order. */
  latest(): StoredCaptureStatus[] {
    const records: StoredCaptureStatus[] = [];
    for (const tool of WebSourceTool.options) {
      const candidates: StoredCaptureStatus[] = [];
      // The ORDER BY makes a started_at tie deterministic, so the candidates
      // arrive newest first and the picker can read them in order.
      for (const row of allRows<CaptureStatusRow>(this.recentStmt, [tool, STATUS_LOOKBACK_ROWS])) {
        const status = fromCaptureStatusAttributes(parseJsonObject(row.attributes));
        if (status === null) continue;
        candidates.push({ tool, observedAt: epochMillisToIso(row.startedAt), status });
      }
      const picked = pickReportedCaptureStatus(candidates);
      if (picked !== undefined) records.push(picked);
    }
    return records;
  }
}
