import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { StoredCaptureStatus } from '@akasecurity/schema';
import {
  CAPTURE_STATUS_RECENCY_MS,
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
 * One seek per site rather than one scan of the whole range: the generated
 * `source_tool` column carries no index of its own, so a query that asks for
 * every site at once re-tests each row against the other site's newest
 * timestamp and degrades quadratically as history accumulates.
 *
 * `/security` issues this read on every request, so it is registered in
 * `test/performance/hot-read-query-plans.test.ts` (which pins the index it
 * runs under) and in `test/performance/capture-status-scale.test.ts` (which
 * pins that it is flat in store history). The plan test alone would not have
 * caught what the scale test does: `source_tool` is not in `idx_audit_type_t`,
 * so the seek for a site with NO rows examines the whole `capture_status`
 * range before it can conclude there is nothing to find — an indexed SEARCH in
 * the plan and linear in the history. Measured before the recency bound below:
 * 0.331 ms at 2,000 rows against 4.389 ms at 20,000, i.e. 13.3x for 10x the
 * rows, and unbounded because `audit_events` has no retention policy. A
 * partial index on (`source_tool`, `started_at`) would make it constant rather
 * than merely bounded; the window is what is in place today.
 */
export class SqliteCaptureStatusRepository {
  private readonly recentStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.recentStmt = db.prepare(
      `SELECT a.started_at AS startedAt, a.attributes AS attributes
         FROM audit_events a
        WHERE a.event_type = 'capture_status'
          AND a.source_tool = ?
          AND a.started_at >= ?
        ORDER BY a.started_at DESC, a.id DESC
        LIMIT ?`,
    );
  }

  /**
   * The reported status per site, in registry order, from the last
   * `CAPTURE_STATUS_RECENCY_MS`.
   *
   * `now` is a required argument rather than a `Date.now()` read, so a caller
   * that already holds a render instant passes THAT one and a test can drive
   * the window without moving the wall clock.
   *
   * A site whose newest report has aged out is omitted, so it derives to
   * `unreported`. That is the point: nothing but the browser extension ever
   * writes these rows, so an uninstalled extension's last verdict would
   * otherwise stand as a live claim for ever with no later report able to
   * clear it.
   */
  latest(now: number): StoredCaptureStatus[] {
    const since = now - CAPTURE_STATUS_RECENCY_MS;
    const records: StoredCaptureStatus[] = [];
    for (const tool of WebSourceTool.options) {
      const candidates: StoredCaptureStatus[] = [];
      // The ORDER BY makes a started_at tie deterministic, so the candidates
      // arrive newest first and the picker can read them in order.
      for (const row of allRows<CaptureStatusRow>(this.recentStmt, [
        tool,
        since,
        STATUS_LOOKBACK_ROWS,
      ])) {
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
