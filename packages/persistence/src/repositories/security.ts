import type { DatabaseSync } from 'node:sqlite';

import {
  CAPTURE_EVENT_TYPES_SQL,
  type EnforcementActionKind,
  type EnforcementActionsResponse,
  type FindingsTimeseriesPoint,
  type FindingsTimeseriesResponse,
  type MttrTrendPoint,
  type MttrTrendResponse,
  type Provider,
  Provider as ProviderSchema,
  RANGE_DAYS,
  type RecentlyResolvedResponse,
  type ResolvedFeedItem,
  type ScanCoverageResponse,
  type Severity,
  type SeveritySummaryResponse,
  type SourceKind,
  type TimeRange,
  type TimeseriesGranularity,
  type TopSource,
  type TopSourcesResponse,
} from '@akasecurity/schema';

import { allRows } from '../internal/rows.ts';
import type { SecurityViews } from '../ports.ts';
import { LATEST_RESOLUTION_BY_KEY_SQL } from './resolution-sql.ts';

const DAY_MS = 86_400_000;

// All severities, highest-first — the contract requires every level present
// (count may be 0), so we project onto this fixed list, not just what GROUP BY found.
const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

// finding.actionTaken → enforcement kind. Partial: allow/log are not enforcement
// and have no entry, so a lookup returns undefined (the caller guards).
const ACTION_TO_KIND: Partial<Record<string, EnforcementActionKind>> = {
  block: 'blocked',
  redact: 'redacted',
  warn: 'warned',
};
const ENFORCEMENT_KINDS: readonly EnforcementActionKind[] = ['blocked', 'redacted', 'warned'];

// Per-provider scan coverage — a curated business fact (constant across the
// range, not a measured per-window metric), following the shared contract so
// read surfaces render identically. Order is the dashboard display order.
// Codex sits below 100 because the Codex CLI does not yet fire PreToolUse/
// PostToolUse for apply_patch (file-write) calls. Covered: prompts, assistant
// responses, Bash command text, worktree scans. NOT covered: file-write
// content, in either direction — the history backfill does not close this gap,
// because it scans conversation messages only and the tool-call reconciler
// records a write's changed paths and byte sizes, never its bytes (see
// plugins/codex/skills/setup/SKILL.md and
// plugins/codex/src/history/transcripts.ts).
// Antigravity sits lower still: its hook contract has no prompt-bearing event
// (PreInvocation carries no prompt text) and no field for rewriting tool args
// or withholding a tool result, so a redact policy can only escalate to a deny
// and PostToolUse is record-only. Tool calls are covered across every tool in
// the CLI; the IDE fires no hooks at all (see
// plugins/antigravity/skills/setup/SKILL.md).
// The two web-chat surfaces sit lowest of the supported rows, and what bounds
// them is structural: content.ts watches ONE element. findComposer() is
// firstMatch(COMPOSER_SELECTORS) — the first match of the first selector that
// matches anything, singular — and content.ts keeps a single composer/unwatch
// pair, so the typed prompt in that one composer is scanned (and blocked,
// redacted or warned) before it leaves the page, while EVERY other way text or
// bytes reach the model is uncovered by construction. That is a property of
// plugins/browser-extension/src/content.ts, not an observation about a vendor's
// markup, so it holds through any redesign.
//
// Three such surfaces are known and none is scanned: assistant responses are
// never read back out of the DOM; an ATTACHMENT is a sibling node rather than
// composer text, so a file added by paperclip, drag-drop or paste egresses with
// no scan, no event and no finding (extractText is extractContentEditableText
// on both adapters and reads the composer element alone); and EDIT-AND-RESEND
// submits from the message being edited rather than the composer, so nothing
// watches it. Treat that list as a floor rather than a partition: the
// one-element bound admits surfaces nobody has enumerated yet, which is why 40
// is a curated position below every terminal-harness row rather than a fraction
// computed from a channel count.
//
// This row also rests on weaker footing than the rows above it, which are
// backed by a documented hook contract. Each adapter's selectors are
// best-effort against a vendor's DOM, and a miss is silent by design
// (findComposer() returns null and the adapter does nothing), so a redesign can
// take real coverage to zero without changing this table.
// Keyed by every `Provider` value rather than an array, so a provider added to
// the enum without a row here is a compile error — an omission the array shape
// this replaced could not catch (see scanCoverage() below for the ordering,
// which is derived from Provider.options). Key order here is deliberately NOT
// Provider's declaration order: scanCoverage() must derive the response order
// from Provider.options rather than from iterating this object, and keeping
// the two orders different is what makes that a test can actually falsify —
// with the two orders coincidentally equal, an implementation that iterates
// this object directly would emit the identical sequence.
const SCAN_COVERAGE: Record<Provider, { coverage: number; supported: boolean }> = {
  antigravity: { coverage: 60, supported: true },
  api: { coverage: 0, supported: false },
  chatgpt: { coverage: 40, supported: true },
  claudeai: { coverage: 40, supported: true },
  claudecode: { coverage: 100, supported: true },
  codex: { coverage: 80, supported: true },
  copilot: { coverage: 0, supported: false },
  cursor: { coverage: 0, supported: false },
};

// Bucket size per range. A table rather than a ternary so adding a range to
// TIME_RANGES is a compile error here too, the way a missing RANGE_DAYS entry is.
const GRANULARITY = {
  '7d': 'day',
  '30d': 'day',
  '3m': 'week',
  '6m': 'week',
} as const satisfies Record<TimeRange, TimeseriesGranularity>;

function granularityFor(range: TimeRange): TimeseriesGranularity {
  return GRANULARITY[range];
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
 * Security dashboard read views over the local store. The adapter
 * fetches AND aggregates here so one call yields the finished @akasecurity/schema
 * response the security widget views consume — the local store IS the
 * security service. Window/bucket/delta math is pure JS over rows fetched per
 * range; the clock is injectable so it is deterministic under test.
 *
 * Two contract gaps are intrinsic to the local store, not omissions:
 *  - top-sources `user` kind: captures carry no userId — the store records no
 *    user identity, since every row in it belongs to this machine — so only
 *    `repo` sources, from audit_events.attributes.repo, are derivable; a `user`
 *    filter returns [].
 *  - recommended-actions: a recommendation engine with no OSS storage — not part
 *    of this port (the web-ui renders an empty card).
 *
 * One store per machine: no query carries an owner predicate.
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
        `SELECT d.severity AS severity,
                COUNT(*) AS count,
                SUM(CASE
                      WHEN e.event_type != 'code_change' THEN 1
                      WHEN f.finding_key IS NULL THEN 0
                      WHEN latest.status = 'resolved' THEN 1
                      ELSE 0
                    END) AS caught,
                SUM(CASE
                      WHEN e.event_type = 'code_change'
                       AND f.finding_key IS NOT NULL
                       AND (latest.status IS NULL OR latest.status != 'resolved') THEN 1
                      ELSE 0
                    END) AS open_at_rest
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
           ON latest.finding_key = f.finding_key
         WHERE e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
         GROUP BY d.severity`,
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
  // business fact (see SCAN_COVERAGE), not a measured per-window metric. Order
  // comes from Provider.options (the enum's declaration order), not from
  // SCAN_COVERAGE's own key order — deliberately, not because object literals
  // leave key order unspecified (ES2015 guarantees insertion order for these
  // non-integer string keys, so iterating SCAN_COVERAGE directly would be
  // reliable too). The reason is the schema comment's promise: the returned
  // order must mirror the generated OpenAPI enum list, which is Provider's
  // contract, not this table's.
  scanCoverage(range: TimeRange): Promise<ScanCoverageResponse> {
    return Promise.resolve({
      range,
      providers: ProviderSchema.options.map((provider) => ({
        provider,
        ...SCAN_COVERAGE[provider],
      })),
    });
  }

  enforcementActions(range: TimeRange): Promise<EnforcementActionsResponse> {
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

  findingsTimeseries(range: TimeRange): Promise<FindingsTimeseriesResponse> {
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
  // (audit_events.started_at), this buckets by resolution time (the latest
  // finding_resolution row's resolved_at) — it's a "resolved in this bucket"
  // trend, not a "detected in this bucket" one. Only findings whose LATEST
  // resolution row (latest-resolution-wins, same correlated subquery as
  // severitySummary — NOT a LEFT JOIN, which would double-count a key with more
  // than one resolution row) is status:'resolved' + method:'fixed-at-source'
  // count; a superseding open/redetected row means the finding is not
  // remediated and is excluded, same invariant as severitySummary. Legacy
  // at-rest findings with finding_key IS NULL can never have a resolution row
  // (the lifecycle is keyed by finding_key), so they cannot reach the driving
  // set below. One raw-row query (fetch the findings with resolution activity in
  // the window + each one's latest resolution status/method/resolved_at) +
  // pure-JS filter/bucket/mean, mirroring this file's other methods.
  mttrTrend(range: TimeRange): Promise<MttrTrendResponse> {
    const granularity = granularityFor(range);
    const bucketMs = (granularity === 'day' ? 1 : 7) * DAY_MS;
    const lenDays = RANGE_DAYS[range];
    const numBuckets = granularity === 'day' ? lenDays : Math.ceil(lenDays / 7);

    // Same day-aligned window as findingsTimeseries, snapshotting the clock once.
    const now = this.now();
    const windowStart = startOfUtcDay(now) - (lenDays - 1) * DAY_MS;

    const rows = allRows<{
      /** Selected for DISTINCT's benefit, not read below — see the note on the SQL. */
      finding_key: string;
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
        // started_at the upsert overwrites onto inspection_findings.audit_event_id.
        // COALESCE onto the parent event's started_at defends against any
        // legacy/edge row the backfill left null.
        `SELECT DISTINCT f.finding_key AS finding_key,
                COALESCE(f.first_detected_at, e.started_at) AS first_detected_at, d.severity AS severity,
                latest.status AS latest_status,
                latest.method AS latest_method,
                latest.resolved_at AS latest_resolved_at
         FROM finding_resolution fr
         CROSS JOIN inspection_findings f ON f.finding_key = fr.finding_key
         CROSS JOIN audit_events e ON e.id = f.audit_event_id
         CROSS JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         LEFT JOIN ${LATEST_RESOLUTION_BY_KEY_SQL} latest
           ON latest.finding_key = f.finding_key
         WHERE fr.resolved_at >= :windowStart
           AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})`,
        // `fr` is a SUPERSET prefilter, not the answer: a finding this method
        // ultimately counts has its LATEST resolution inside the window, which
        // implies a resolution row at/after the window start exists, so nothing
        // wanted is dropped. The exact latest-wins + status/method + window gate
        // stays in JS below, dialect-agnostic. `f.finding_key IS NOT NULL` is
        // implied rather than dropped — the join key comes from
        // finding_resolution, whose finding_key is NOT NULL.
        //
        // IT IS THE DRIVING TABLE THAT MAKES THAT PREFILTER A BOUND, which is
        // the correction this replaced. Spelled as an `EXISTS` in the WHERE it
        // READ as a bound and was not one: SQLite drove from `audit_events` on
        // event_type, joined every capture event to its findings, and evaluated
        // the EXISTS last — bounding the RESULT and not the scan, so a 7d request
        // still cost the store's whole trackable history. Measured at 44.6 ms on
        // 50,000 events and 171.3 ms on 150,000 — linear in the STORE, and in
        // both cases returning rows for a window holding a fraction of it.
        //
        // Two things carry it, and they answer DIFFERENT halves — which is worth
        // stating precisely, because the obvious reading (both are needed for the
        // speed) is wrong and was measured to be wrong:
        //
        //  - **`CROSS JOIN`** is the whole of the store-size fix. In SQLite the
        //    keyword is semantically identical to JOIN and exists only to stop the
        //    tables being reordered; with plain JOINs the planner puts `e` back on
        //    the outside, because with no ANALYZE statistics it prices
        //    `event_type IN (...)` as a selective probe. Reverting it alone takes
        //    the 2k->20k flatness ratio from 1.32 to 16.87.
        //  - **`idx_finding_resolution_resolved_at`** (migration 0021) makes
        //    `resolved_at >= :windowStart` a range SEARCH instead of a bare
        //    `SCAN fr` — finding_key was this table's only index before it, so the
        //    range had none. It buys NO flatness in store size: remove it and the
        //    ratio above does not move, because the latest-resolution derived
        //    table already passes over the whole of finding_resolution, so this
        //    read is O(resolutions) either way and resolutions are not the store.
        //    What it buys is the criterion `hot-read-query-plans.test.ts` enforces
        //    — no hot read may pass over a table with no index — and that is the
        //    guard that goes red when it is dropped. Neither test catches the
        //    other's defect.
        //
        // SELECT DISTINCT is a CORRECTNESS requirement of driving from `fr`, not a
        // tidy-up. finding_resolution is append-only, so a key that was fixed,
        // redetected and fixed again carries several rows inside one window and
        // matches once per row — and the value below is a MEAN, so a key matched
        // three times is a key weighted three times.
        //
        // The skew is easy to argue away and the argument is wrong, so it is worth
        // recording. Duplicate rows for ONE key are identical (every projected
        // column is per-key: `latest.*` is latest-wins, `first_detected_at` is
        // preserved), so sums and counts scale together and that key's own mean
        // does not move. What moves is a bucket holding TWO findings that duplicate
        // UNEQUALLY: three rows for a 5.9-day fix and one for a 1.9-day fix average
        // 4.9 days weighted against 3.9 unweighted. Measured, and pinned by
        // `security.test.ts`'s "weights a finding ONCE however many resolution rows
        // it has inside the window" — which needed a fixture built for it, since no
        // single-key case can show it.
        //
        // `finding_key` is selected to make the DISTINCT dedup by KEY rather than
        // by value tuple. On the other columns alone, two genuinely different
        // findings sharing a severity, a first-detection event and a resolution
        // instant — one commit fixing two secrets in one file — are one tuple, and
        // collapsing them would under-count in the other direction.
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
    range: TimeRange,
    opts: { limit?: number; kind?: SourceKind } = {},
  ): Promise<TopSourcesResponse> {
    const limit = opts.limit ?? 5;
    // Events carry no userId, so user sources aren't derivable.
    if (opts.kind === 'user') return Promise.resolve({ range, items: [] });

    const now = this.now();
    const from = now - RANGE_DAYS[range] * DAY_MS;
    // Rank repos by findings in the window. attributes.repo is extracted in SQL
    // via json_extract; rows without a repo are excluded. Ranked + sliced in
    // SQL — tie-break on repo for a stable order.
    const rows = allRows<{ repo: string; c: number }>(
      this.db.prepare(
        `SELECT json_extract(e.attributes, '$.repo') AS repo, count(*) AS c
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         WHERE e.started_at >= :from AND e.started_at < :to
           AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
           AND json_extract(e.attributes, '$.repo') IS NOT NULL
           AND json_extract(e.attributes, '$.repo') != ''
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
  // same latest-resolution-wins derived table as severitySummary / mttrTrend
  // (NOT a plain JOIN, which would surface every historical resolution row for
  // a key rather than just its current disposition). A key whose latest row is
  // a superseding 'open'/'redetected' row (the same secret came back) is
  // excluded — it is not currently resolved. Legacy at-rest findings with
  // finding_key IS NULL are excluded outright (the resolution lifecycle can
  // never attach to them). Path comes from the finding's parent event
  // (event_type 'code_change', attributes.file_path) — mirrors resolutions.ts's
  // openAtRestStmt accessor. Ordered by resolved_at DESC, capped at `limit`.
  //
  // THE RESOLUTION SET DRIVES THIS QUERY, and that is a correctness property of
  // the plan rather than a preference. Written the other way round — driving
  // from inspection_findings/audit_events with `latest` LEFT JOINed on — SQLite
  // cannot use the join key: `f` is reached FROM `latest` by finding_key, so
  // `latest` gets probed on (rn, status, method) instead and the plan enumerates
  // every (code_change event x resolved key) pair before `f` can reject it. That
  // is a cross product, and it is quadratic in the store: measured at 10,966 ms
  // on a corpus of 50,000 events carrying 2,051 resolutions, against 20 rows
  // returned. It was invisible for as long as it was, and reported at 8 ms,
  // because an empty finding_resolution table makes the inner side empty and the
  // cross product collapses to nothing — so the shape is only observable on a
  // corpus that seeds resolutions.
  //
  // Driving from `latest` instead makes every step below it a unique-index or
  // primary-key lookup (uq_inspection_findings_key, then audit_events' own PK),
  // so the cost is the derived table's own — linear in resolutions, which is
  // what this feed is legitimately about.
  //
  // CROSS JOIN is what actually pins that, and it is load-bearing rather than
  // decorative: in SQLite the keyword is semantically identical to JOIN and
  // exists only to stop the optimizer reordering the tables. Written as plain
  // JOINs in this order the planner puts `e` back on the outside — it has no
  // ANALYZE statistics to price the alternatives with, so it takes
  // `event_type = 'code_change'` for a selective index probe and rebuilds the
  // cross product. The FROM order alone was measured to change the plan not at
  // all.
  //
  // The LEFT JOIN it replaced was already an inner join in effect: three
  // `latest.*` predicates sit in the WHERE, and each of them is false for a
  // null-extended row. Spelling it JOIN changes no row and stops the plan
  // reading as though the findings side could drive.
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
                d.rule_id AS rule_id,
                d.severity AS severity,
                json_extract(e.attributes, '$.file_path') AS path,
                COALESCE(f.first_detected_at, e.started_at) AS first_detected_at,
                latest.resolved_at AS latest_resolved_at
         FROM ${LATEST_RESOLUTION_BY_KEY_SQL} latest
         CROSS JOIN inspection_findings f ON f.finding_key = latest.finding_key
         CROSS JOIN audit_events e ON e.id = f.audit_event_id
         CROSS JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         WHERE latest.status = 'resolved'
           AND latest.method = 'fixed-at-source'
           AND latest.resolved_at IS NOT NULL
           AND e.event_type = 'code_change'
         ORDER BY latest.resolved_at DESC
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
  // epoch-millis timestamp. started_at is an INTEGER column, so the bounds stay
  // numeric and the JS aggregations bucket/split on ms directly.
  private findingsInRange(fromMs: number, toMs: number): FindingTimeRow[] {
    const rows = allRows<{
      occurred_at: number;
      severity: string;
      action_taken: string;
    }>(
      this.db.prepare(
        `SELECT e.started_at AS occurred_at, d.severity AS severity, f.action_taken AS action_taken
         FROM inspection_findings f
         JOIN audit_events e ON e.id = f.audit_event_id
         JOIN inspection_definitions d ON d.id = f.inspection_definition_id
         WHERE e.started_at >= :from AND e.started_at < :to
           AND e.event_type IN (${CAPTURE_EVENT_TYPES_SQL})
         ORDER BY e.started_at`,
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
