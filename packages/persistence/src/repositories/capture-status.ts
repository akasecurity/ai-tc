import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { ReportedCaptureDocument, StoredCaptureStatus } from '@akasecurity/schema';
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
  rootSessionId: string | null;
}

/**
 * How many of a site's newest rows one read looks at.
 *
 * It has to cover two things at once. Within one document, the read reports
 * the newest row that observed the site's turn path (see
 * `pickReportedCaptureStatus`), so it must see past a run of watching-only
 * reports — a tab relays one when its tap patches and another when the page
 * unloads, so an untouched tab writes two. Across documents, every
 * concurrently-reporting document has to be IN the window at all, or a chatty
 * tab's own reports push a quiet drifting one out of it and the drift is
 * invisible again for a different reason than the one the fold fixed.
 *
 * Bounded because this walks the `capture_status` range, and a constant
 * because a window proportional to the store would put this read's cost back
 * on the history (`capture-status-scale.test.ts` is what holds that). Past
 * this many rows the older documents are treated as stale.
 */
const STATUS_LOOKBACK_ROWS = 128;

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
 * the plan and linear in the history, and unbounded because `audit_events` has
 * no retention policy. The FIGURES live in that scale suite's own header
 * rather than here — they were re-taken when `STATUS_LOOKBACK_ROWS` moved
 * 32 -> 128, and one measurement quoted in two files is one that goes out of
 * step. A partial index on (`source_tool`, `started_at`) would make this
 * constant rather than merely bounded; the window is what is in place today.
 *
 * The index is not a BOUND, and the write side is why. Every report is a fresh
 * row — two per tab load per site, the tap-patched one and the `pagehide` one,
 * and one more per transition — nothing ever collapses them, and `audit_events`
 * carries no row retention, so the `capture_status` range only grows. The plan
 * is a clean `SEARCH USING INDEX idx_audit_type_t (event_type=?)`, but that
 * index is keyed on (event_type, started_at) and NOT on `source_tool`: the seek
 * for one site walks the newer rows of the OTHER site first, so this read's
 * cost grows with a heavily used sibling site's history even though the answer
 * is `LIMIT`-bounded. `retention-surface.test.ts` pins which tables are swept
 * and which are not, so adding a sweep here later is a deliberate edit rather
 * than a quiet one.
 */
export class SqliteCaptureStatusRepository {
  private readonly recentStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.recentStmt = db.prepare(
      `SELECT a.started_at AS startedAt,
              a.attributes AS attributes,
              a.root_session_id AS rootSessionId
         FROM audit_events a
        WHERE a.event_type = 'capture_status'
          AND a.source_tool = ?
          AND a.started_at >= ?
        ORDER BY a.started_at DESC, a.id DESC
        LIMIT ?`,
    );
  }

  /**
   * Every document that reported for a site, in registry order by site, from
   * the last `CAPTURE_STATUS_RECENCY_MS`.
   *
   * SEVERAL per site, not one: a browser is many documents and each reports
   * for itself, so one row per site is a choice about which of them a user
   * sees — and the newest is the wrong one, since a healthy tab writing a
   * fresh report would hide a drifting tab's verdict, which is the whole
   * reason these rows exist. The pick WITHIN a document is made here (the
   * unchanged `pickReportedCaptureStatus`, over that document's own rows);
   * choosing between documents belongs where the state semantics live, and
   * that is `reportedCaptureDocumentForSite` in `@akasecurity/detections` —
   * this package may not import it.
   *
   * `now` is a required argument rather than a `Date.now()` read, so a caller
   * that already holds a render instant passes THAT one and a test can drive
   * the window without moving the wall clock.
   *
   * A site whose reports have all aged out contributes nothing, so it derives
   * to `unreported`. That is the point: nothing but the browser extension ever
   * writes these rows, so an uninstalled extension's last verdict would
   * otherwise stand as a live claim for ever with no later report able to
   * clear it.
   */
  latest(now: number): ReportedCaptureDocument[] {
    const since = now - CAPTURE_STATUS_RECENCY_MS;
    const documents: ReportedCaptureDocument[] = [];
    for (const tool of WebSourceTool.options) {
      // Keyed on the root itself, `null` included — a row written before the
      // host stamped one is indistinguishable from another such row, so they
      // are one document rather than one each.
      const rows = new Map<string | null, StoredCaptureStatus[]>();
      const lastWord = new Map<string | null, { at: string; closed: boolean }>();
      for (const row of allRows<CaptureStatusRow>(this.recentStmt, [
        tool,
        since,
        STATUS_LOOKBACK_ROWS,
      ])) {
        const status = fromCaptureStatusAttributes(parseJsonObject(row.attributes));
        if (status === null) continue;
        const record = { tool, observedAt: epochMillisToIso(row.startedAt), status };
        const group = rows.get(row.rootSessionId);
        if (group === undefined) {
          rows.set(row.rootSessionId, [record]);
          // The ORDER BY is DESC, so a group's first row is its newest and
          // this is the document's last word. Recorded here rather than
          // derived below because the picker may choose an older row.
          lastWord.set(row.rootSessionId, { at: record.observedAt, closed: status.closed });
        } else {
          // Newest first within the group too, which is the order the picker
          // reads its candidates in.
          group.push(record);
        }
      }
      for (const [root, candidates] of rows) {
        const picked = pickReportedCaptureStatus(candidates);
        const last = lastWord.get(root);
        if (picked === undefined || last === undefined) continue;
        documents.push({
          ...picked,
          ...(root === null ? {} : { rootSessionId: root }),
          lastReportAt: last.at,
          closed: last.closed,
        });
      }
    }
    return documents;
  }
}
