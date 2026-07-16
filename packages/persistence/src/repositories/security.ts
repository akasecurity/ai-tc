import type { DatabaseSync } from 'node:sqlite';

import type {
  EnforcementActionKind,
  EnforcementActionsResponse,
  FindingsTimeseriesPoint,
  FindingsTimeseriesResponse,
  MttrTrendPoint,
  MttrTrendResponse,
  Provider,
  RecentlyResolvedResponse,
  ResolvedFeedItem,
  ScanCoverageResponse,
  SecurityRange,
  Severity,
  SeveritySummaryResponse,
  SourceKind,
  TimeseriesGranularity,
  TopSource,
  TopSourcesResponse,
} from '@akasecurity/schema';

import { allRows } from '../internal/rows.ts';
import type { SecurityViews } from '../ports.ts';
import { LATEST_RESOLUTION_BY_KEY_SQL } from './resolution-sql.ts';

const DAY_MS = 86_400_000;

// All severities, highest-first — the contract requires every level present
// (count may be 0), so we project onto this fixed list, not just what GROUP BY found.
const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

// Window length per range, in days. 3m/6m use 90/180-day rolling approximations
// (no calendar-month math) — fine for a rolling dashboard window.
const RANGE_DAYS: Record<SecurityRange, number> = { '7d': 7, '30d': 30, '3m': 90, '6m': 180 };

// finding.actionTaken → enforcement kind. Partial: allow/log are not enforcement
// and have no entry, so a lookup returns undefined (the caller guards).
const ACTION_TO_KIND: Partial<Record<string, EnforcementActionKind>> = {
  block: 'blocked',
  redact: 'redacted',
  warn: 'warned',
};
const ENFORCEMENT_KINDS: readonly EnforcementActionKind[] = ['blocked', 'redacted', 'warned'];

// Per-provider scan coverage. Initial release scans Claude Code only — a curated
// business fact (constant across the range, not a measured per-window metric),
// following the shared contract so read surfaces render identically. Order
// is the dashboard display order.
const SCAN_COVERAGE: readonly { provider: Provider; coverage: number; supported: boolean }[] = [
  { provider: 'claudecode', coverage: 100, supported: true },
  { provider: 'cursor', coverage: 0, supported: false },
  { provider: 'codex', coverage: 0, supported: false },
  { provider: 'chatgpt', coverage: 0, supported: false },
  { provider: 'copilot', coverage: 0, supported: false },
  { provider: 'api', coverage: 0, supported: false },
];

// 7d/30d bucket by day; 3m/6m by week.
function granularityFor(range: SecurityRange): TimeseriesGranularity {
  return range === '7d' || range === '30d' ? 'day' : 'week';
}

// UTC midnight of the given epoch-ms (epoch 0 is itself a UTC midnight).
function startOfUtcDay(ms: number): number {
  return Math.floor(ms / DAY_MS) * DAY_MS;
}

function toUtcDateString(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

// The timeseries plots critical/high/medium only (low omitted by contract).
function isTimeseriesSeverity(s: string): s is 'critical' | 'high' | 'medium' {
  return s === 'critical' || s === 'high' || s === 'medium';
}

// One finding within a window, carrying its parent event's epoch-millis timestamp
// (findings have no timestamp of their own). The aggregations bucket/split these.
interface FindingTimeRow {
  occurredAt: number;
  severity: string;
  actionTaken: string;
}

/**
 * Security dashboard read views over the tenant-free local store. The adapter
 * fetches AND aggregates here so one call yields the finished @akasecurity/schema
 * response the security widget views consume — the local store IS the
 * security service. Window/bucket/delta math is pure JS over rows fetched per
 * range; the clock is injectable so it is deterministic under test.
 *
 * Two contract gaps are intrinsic to the local store, not omissions:
 *  - top-sources `user` kind: OSS events carry no userId (the store is
 *    tenant-free, single-tenant), so only `repo` sources — from
 *    events.metadata.repo — are derivable; a `user` filter returns [].
 *  - recommended-actions: a recommendation engine with no OSS storage — not part
 *    of this port (the web-ui renders an empty card).
 *
 * Single-tenant: no tenant predicate on any query.
 */
export class SqliteSecurityRepository implements SecurityViews {
  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number = () => Date.now(),
  ) {}

  // Status-aware: every finding is classified by origin (its parent event's
  // kind — 'code_change' is at-rest, everything else is in-flight) and, for
  // at-rest findings, whether its finding_key's LATEST finding_resolution row
  // (max created_at, not "does ANY row exist") has status 'resolved' — mirrors
  // SqliteResolutionsRepository's LATEST-RESOLUTION-WINS convention. "Any row
  // exists" would let a fixed-at-source key that is later redetected (the same
  // secret re-added) stay silently "caught" forever under its stale resolved
  // row; latest-wins lets the scanner supersede it with a fresh status:'open'
  // row (see scan.ts's reopenRedetectedFindings) so the invariant holds: a
  // finding_key present in the current scan is OPEN, regardless of history.
  // In-flight findings are born caught (enforcement already ran); at-rest
  // findings are caught only once their latest disposition is resolved,
  // otherwise they are open-at-rest.
  //
  // NOTE for future manual-resolution writers: only latest status
  // 'resolved' counts as caught above. When acknowledged/dismissed/
  // false-positive manual dispositions land, this must keep filtering by
  // status/method — 'acknowledged' is accepted risk, not a fix, and must NOT
  // be bucketed as caught alongside 'resolved'.
  //
  // Legacy at-rest findings from pre-branch scans carry finding_key = NULL —
  // the resolution lifecycle is keyed by finding_key, so it can never attach a
  // disposition to (or clear) one of these on re-scan. They are excluded from
  // both caught and openAtRest (untracked, not "needs remediation forever"),
  // but still counted in total/count below — this keeps this predicate
  // consistent with SqliteResolutionsRepository.openAtRestKeysForPath, which
  // already filters `finding_key IS NOT NULL`.
  //
  // One GROUP BY aggregate: the result set stays O(distinct severities) no
  // matter how many findings the store has accumulated (this backs `aka stats`
  // and the dashboard severity card, both hot paths on a table that only
  // grows). The latest-resolution status comes from the shared derived-table
  // fragment (see resolution-sql.ts) rather than a correlated subquery per
  // finding — its rn = 1 filter is also what makes the LEFT JOIN safe against
  // double-counting a key that accumulated several append-only rows.
  severitySummary(): Promise<SeveritySummaryResponse> {
    const rows = allRows<{
      severity: string;
      count: number;
      caught: number;
      open_at_rest: number;
    }>(
      this.db.prepare(
        `SELECT f.severity AS severity,
                COUNT(*) AS count,
                SUM(CASE
                      WHEN e.kind != 'code_change' THEN 1
                      WHEN f.finding_key IS NULL THEN 0
                      WHEN latest.status = 'resolved' THEN 1
                      ELSE 0
                    END) AS caught,
                SUM(CASE
                      WHEN e.kind = 'code_change'
                       AND f.finding_key IS NOT NULL
                       AND (latest.status IS NULL OR latest.status != 'resolved') THEN 1
                      ELSE 0
                    END) AS open_at_rest
         FROM findings f
         JOIN events e ON e.id = f.event_id
         LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
           ON latest.finding_key = f.finding_key
         GROUP BY f.severity`,
      ),
    );

    // Bucket semantics (mirrors the CASEs above): in-flight is born caught;
    // trackable at-rest is caught only when its latest resolution is
    // 'resolved', otherwise open-at-rest; legacy untracked at-rest
    // (finding_key IS NULL) lands in NEITHER bucket, only in count.
    const byRow = new Map(rows.map((r) => [r.severity, r]));
    const bySeverity = SEVERITIES.map((severity) => ({
      severity,
      count: byRow.get(severity)?.count ?? 0,
      caught: byRow.get(severity)?.caught ?? 0,
      openAtRest: byRow.get(severity)?.open_at_rest ?? 0,
    }));
    const total = bySeverity.reduce((sum, s) => sum + s.count, 0);
    const needsRemediation = bySeverity.reduce((sum, s) => sum + s.openAtRest, 0);

    return Promise.resolve({ total, needsRemediation, bySeverity });
  }

  // Range is echoed but does not change the result today — coverage is a constant
  // business fact (see SCAN_COVERAGE), not a measured per-window metric.
  scanCoverage(range: SecurityRange): Promise<ScanCoverageResponse> {
    return Promise.resolve({ range, providers: SCAN_COVERAGE.map((p) => ({ ...p })) });
  }

  enforcementActions(range: SecurityRange): Promise<EnforcementActionsResponse> {
    const lenMs = RANGE_DAYS[range] * DAY_MS;
    const now = this.now();
    const currentStart = now - lenMs;
    const priorStart = now - 2 * lenMs;

    // One fetch spans both windows ([priorStart, now)); split in JS by occurredAt
    // so current vs. preceding-window counts share a single query.
    const rows = this.findingsInRange(priorStart, now);

    const current: Record<EnforcementActionKind, number> = { blocked: 0, redacted: 0, warned: 0 };
    const prior: Record<EnforcementActionKind, number> = { blocked: 0, redacted: 0, warned: 0 };
    for (const r of rows) {
      const kind = ACTION_TO_KIND[r.actionTaken];
      if (!kind) continue; // allow/log — not enforcement
      if (r.occurredAt >= currentStart) current[kind]++;
      else prior[kind]++;
    }

    const actions = ENFORCEMENT_KINDS.map((kind) => ({
      kind,
      count: current[kind],
      delta: current[kind] - prior[kind],
    }));
    const total = actions.reduce((sum, a) => sum + a.count, 0);

    return Promise.resolve({ range, total, actions });
  }

  findingsTimeseries(range: SecurityRange): Promise<FindingsTimeseriesResponse> {
    const granularity = granularityFor(range);
    const bucketMs = (granularity === 'day' ? 1 : 7) * DAY_MS;
    const lenDays = RANGE_DAYS[range];
    const numBuckets = granularity === 'day' ? lenDays : Math.ceil(lenDays / 7);

    // Window spans lenDays days ending today, DAY-ALIGNED to UTC midnight; buckets
    // tile forward from windowStart (the final week bucket is partial). Snapshot
    // the clock ONCE so a read crossing UTC midnight can't drop a just-arrived row.
    const now = this.now();
    const windowStart = startOfUtcDay(now) - (lenDays - 1) * DAY_MS;
    const rows = this.findingsInRange(windowStart, now);

    const points: FindingsTimeseriesPoint[] = Array.from({ length: numBuckets }, (_, i) => ({
      timestamp: toUtcDateString(windowStart + i * bucketMs),
      critical: 0,
      high: 0,
      medium: 0,
    }));
    for (const r of rows) {
      const idx = Math.floor((r.occurredAt - windowStart) / bucketMs);
      const bucket = points[idx];
      if (!bucket) continue; // out of window
      if (isTimeseriesSeverity(r.severity)) bucket[r.severity]++;
    }

    return Promise.resolve({ range, granularity, points });
  }

  // Mean time-to-remediate per bucket, split by severity — a sibling of
  // findingsTimeseries that reuses the same window/bucket/UTC math, but buckets
  // on a different timestamp: findingsTimeseries buckets by first-detection
  // (events.occurred_at), this buckets by resolution time (the latest
  // finding_resolution row's resolved_at) — it's a "resolved in this bucket"
  // trend, not a "detected in this bucket" one. Only findings whose LATEST
  // resolution row (latest-resolution-wins, same correlated subquery as
  // severitySummary — NOT a LEFT JOIN, which would double-count a key with more
  // than one resolution row) is status:'resolved' + method:'fixed-at-source'
  // count; a superseding open/redetected row means the finding is not
  // remediated and is excluded, same invariant as severitySummary. Legacy
  // at-rest findings with finding_key IS NULL can never have a resolution row
  // (the lifecycle is keyed by finding_key), so the SQL guard excludes them
  // outright. One raw-row query (fetch every trackable finding + its latest
  // resolution's status/method/resolved_at) + pure-JS filter/bucket/mean,
  // mirroring this file's other methods.
  mttrTrend(range: SecurityRange): Promise<MttrTrendResponse> {
    const granularity = granularityFor(range);
    const bucketMs = (granularity === 'day' ? 1 : 7) * DAY_MS;
    const lenDays = RANGE_DAYS[range];
    const numBuckets = granularity === 'day' ? lenDays : Math.ceil(lenDays / 7);

    // Same day-aligned window as findingsTimeseries, snapshotting the clock once.
    const now = this.now();
    const windowStart = startOfUtcDay(now) - (lenDays - 1) * DAY_MS;

    const rows = allRows<{
      first_detected_at: number;
      severity: string;
      latest_status: string | null;
      latest_method: string | null;
      latest_resolved_at: number | null;
    }>(
      this.db.prepare(
        // first_detected_at is the PRESERVED first-detection time (set once on a
        // finding's INSERT, never overwritten on the re-detection upsert), so MTTR
        // measures from first sighting — not the latest re-scan's event, whose
        // occurred_at the upsert overwrites onto findings.event_id. COALESCE onto
        // the parent event's occurred_at defends against any legacy/edge row the
        // backfill left null.
        `SELECT COALESCE(f.first_detected_at, e.occurred_at) AS first_detected_at, f.severity AS severity,
                (
                  SELECT fr.status FROM finding_resolution fr
                   WHERE fr.finding_key = f.finding_key
                   ORDER BY fr.created_at DESC, fr.rowid DESC
                   LIMIT 1
                ) AS latest_status,
                (
                  SELECT fr.method FROM finding_resolution fr
                   WHERE fr.finding_key = f.finding_key
                   ORDER BY fr.created_at DESC, fr.rowid DESC
                   LIMIT 1
                ) AS latest_method,
                (
                  SELECT fr.resolved_at FROM finding_resolution fr
                   WHERE fr.finding_key = f.finding_key
                   ORDER BY fr.created_at DESC, fr.rowid DESC
                   LIMIT 1
                ) AS latest_resolved_at
         FROM findings f JOIN events e ON e.id = f.event_id
         WHERE f.finding_key IS NOT NULL
           AND EXISTS (
             SELECT 1 FROM finding_resolution fr
              WHERE fr.finding_key = f.finding_key
                AND fr.resolved_at >= :windowStart
           )`,
        // The EXISTS is a SUPERSET prefilter that bounds the scan to keys with
        // any resolution activity at/after the window start — a row this method
        // ultimately counts has its LATEST resolution inside the window, which
        // implies such a row exists, so nothing wanted is dropped. The exact
        // latest-wins + status/method + window gate stays in JS below,
        // dialect-agnostic. Without this, a
        // 7d request evaluated the store's entire trackable-findings history.
      ),
      { windowStart },
    );

    // Sum + count per `${bucketIndex}:${severity}`, so the mean is computed
    // once at the end rather than materializing every raw MTTR.
    const sums = new Map<string, number>();
    const counts = new Map<string, number>();
    for (const r of rows) {
      if (r.latest_status !== 'resolved' || r.latest_method !== 'fixed-at-source') continue;
      if (r.latest_resolved_at == null) continue;
      if (r.latest_resolved_at < windowStart || r.latest_resolved_at >= now) continue;
      const idx = Math.floor((r.latest_resolved_at - windowStart) / bucketMs);
      if (idx < 0 || idx >= numBuckets) continue; // out of window
      const key = `${String(idx)}:${r.severity}`;
      // Clamped per row: resolved-before-first-detected is reachable without a
      // local bug (finding_key has no machine component, so two machines share
      // a key; a skewed clock's first detection can postdate another machine's
      // fix — and the COALESCE fallback can inject a later re-scan time). The
      // contract is nonnegative; clamping per row (not per mean) keeps the
      // average honest instead of letting one inverted row drag it negative.
      const mttr = Math.max(0, r.latest_resolved_at - r.first_detected_at);
      sums.set(key, (sums.get(key) ?? 0) + mttr);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }

    const points: MttrTrendPoint[] = Array.from({ length: numBuckets }, (_, i) => {
      const bySeverity = {} as MttrTrendPoint['bySeverity'];
      for (const severity of SEVERITIES) {
        const key = `${String(i)}:${severity}`;
        const count = counts.get(key) ?? 0;
        bySeverity[severity] = count > 0 ? (sums.get(key) ?? 0) / count : null;
      }
      return { timestamp: toUtcDateString(windowStart + i * bucketMs), bySeverity };
    });

    return Promise.resolve({ range, granularity, points });
  }

  topSources(
    range: SecurityRange,
    opts: { limit?: number; kind?: SourceKind } = {},
  ): Promise<TopSourcesResponse> {
    const limit = opts.limit ?? 5;
    // OSS events carry no userId (tenant-free), so user sources aren't derivable.
    if (opts.kind === 'user') return Promise.resolve({ range, items: [] });

    const now = this.now();
    const from = now - RANGE_DAYS[range] * DAY_MS;
    // Rank repos by findings in the window. metadata.repo is extracted in SQL via
    // json_extract (mirrors the events repo's JSON handling); rows without a repo
    // are excluded. Ranked + sliced in SQL — tie-break on repo for a stable order.
    const rows = allRows<{ repo: string; c: number }>(
      this.db.prepare(
        `SELECT json_extract(e.metadata, '$.repo') AS repo, count(*) AS c
         FROM findings f JOIN events e ON e.id = f.event_id
         WHERE e.occurred_at >= :from AND e.occurred_at < :to
           AND json_extract(e.metadata, '$.repo') IS NOT NULL
           AND json_extract(e.metadata, '$.repo') != ''
         GROUP BY repo
         ORDER BY c DESC, repo
         LIMIT :limit`,
      ),
      { from, to: now, limit },
    );

    const items: TopSource[] = rows.map((r) => ({
      id: `repo_${r.repo}`,
      name: r.repo,
      kind: 'repo',
      findingsCount: r.c,
    }));

    return Promise.resolve({ range, items });
  }

  // Recently-resolved activity feed: findings whose finding_key's LATEST
  // finding_resolution row is status:'resolved'/method:'fixed-at-source' —
  // same latest-resolution-wins correlated subquery as severitySummary /
  // mttrTrend (NOT a plain JOIN, which would surface every historical
  // resolution row for a key rather than just its current disposition). A key
  // whose latest row is a superseding 'open'/'redetected' row (the same
  // secret came back) is excluded — it is not currently resolved. Legacy
  // at-rest findings with finding_key IS NULL are excluded outright (the
  // resolution lifecycle can never attach to them). Path comes from the
  // finding's parent event (kind 'code_change', metadata.filePath) — mirrors
  // resolutions.ts's openAtRestStmt accessor. Ordered by resolved_at DESC,
  // capped at `limit`.
  recentlyResolved(limit = 20): Promise<RecentlyResolvedResponse> {
    const rows = allRows<{
      finding_key: string;
      rule_id: string;
      severity: Severity;
      path: string | null;
      first_detected_at: number;
      latest_resolved_at: number;
    }>(
      this.db.prepare(
        `SELECT f.finding_key AS finding_key,
                f.rule_id AS rule_id,
                f.severity AS severity,
                json_extract(e.metadata, '$.filePath') AS path,
                COALESCE(f.first_detected_at, e.occurred_at) AS first_detected_at,
                (
                  SELECT fr.resolved_at FROM finding_resolution fr
                   WHERE fr.finding_key = f.finding_key
                   ORDER BY fr.created_at DESC, fr.rowid DESC
                   LIMIT 1
                ) AS latest_resolved_at
         FROM findings f JOIN events e ON e.id = f.event_id
         WHERE e.kind = 'code_change'
           AND f.finding_key IS NOT NULL
           AND (
             SELECT fr.status FROM finding_resolution fr
              WHERE fr.finding_key = f.finding_key
              ORDER BY fr.created_at DESC, fr.rowid DESC
              LIMIT 1
           ) = 'resolved'
           AND (
             SELECT fr.method FROM finding_resolution fr
              WHERE fr.finding_key = f.finding_key
              ORDER BY fr.created_at DESC, fr.rowid DESC
              LIMIT 1
           ) = 'fixed-at-source'
           AND (
             SELECT fr.resolved_at FROM finding_resolution fr
              WHERE fr.finding_key = f.finding_key
              ORDER BY fr.created_at DESC, fr.rowid DESC
              LIMIT 1
           ) IS NOT NULL
         ORDER BY latest_resolved_at DESC
         LIMIT :limit`,
      ),
      { limit },
    );

    const items: ResolvedFeedItem[] = rows.map((r) => ({
      findingKey: r.finding_key,
      ruleId: r.rule_id,
      severity: r.severity,
      path: r.path ?? '',
      resolvedAt: new Date(r.latest_resolved_at).toISOString(),
      // Preserved first-detection time (see the mttrTrend COALESCE note) — the
      // finding's original sighting, not the latest re-scan's event.
      detectedAt: new Date(r.first_detected_at).toISOString(),
    }));

    return Promise.resolve({ items });
  }

  // Findings whose parent event occurred in [fromMs, toMs), with the parent's
  // epoch-millis timestamp. occurred_at is an INTEGER column, so the bounds stay
  // numeric and the JS aggregations bucket/split on ms directly.
  private findingsInRange(fromMs: number, toMs: number): FindingTimeRow[] {
    const rows = allRows<{
      occurred_at: number;
      severity: string;
      action_taken: string;
    }>(
      this.db.prepare(
        `SELECT e.occurred_at AS occurred_at, f.severity AS severity, f.action_taken AS action_taken
         FROM findings f JOIN events e ON e.id = f.event_id
         WHERE e.occurred_at >= :from AND e.occurred_at < :to
         ORDER BY e.occurred_at`,
      ),
      { from: fromMs, to: toMs },
    );
    return rows.map((r) => ({
      occurredAt: r.occurred_at,
      severity: r.severity,
      actionTaken: r.action_taken,
    }));
  }
}
