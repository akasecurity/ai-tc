// DRAFT — Security dashboard read contracts (see docs/api/reference.md).
// Responses are SEMANTIC, not presentational: no color/icon/label fields — the
// frontend maps those from the enums. None of these shapes carry tenancy or
// user-scoping fields.
import { z } from 'zod';

import { Severity } from './finding.ts';
import { DEFAULT_TIME_RANGE, TIME_RANGES, TimeRange } from './ranges.ts';

// GET /v1/security/findings/severity-summary
//
// NOT range-scoped. The contract calls these "open (unresolved)" findings, but
// the findings table is append-only with NO resolution state today — so this
// counts ALL findings per severity. Revisit when a finding lifecycle exists.
export const SeveritySummaryItem = z
  .object({
    severity: Severity,
    count: z.number().int().nonnegative(),
    // Resolution-aware breakdown (optional, additive). Populated once findings
    // carry lifecycle state: `caught` = handled in-flight (enforced); `openAtRest`
    // = still open with no in-flight enforcement (needs remediation). Absent on the
    // legacy count-only response until the resolution feature lands.
    caught: z.number().int().nonnegative().optional(),
    openAtRest: z.number().int().nonnegative().optional(),
  })
  .meta({ id: 'SeveritySummaryItem' });
export type SeveritySummaryItem = z.infer<typeof SeveritySummaryItem>;

export const SeveritySummaryResponse = z
  .object({
    // Sum of bySeverity[].count.
    total: z.number().int().nonnegative(),
    // Findings still open at rest (sum of bySeverity[].openAtRest). Optional and
    // additive — absent on the legacy response until the resolution feature lands.
    needsRemediation: z.number().int().nonnegative().optional(),
    // All four severity levels are always present (count may be 0).
    bySeverity: z.array(SeveritySummaryItem),
  })
  .meta({ id: 'SeveritySummaryResponse' });
export type SeveritySummaryResponse = z.infer<typeof SeveritySummaryResponse>;

// An unsupported value fails Zod validation → 400 (shared VALIDATION_ERROR
// envelope, consistent with every other query param in this API).
//
// The inline enum is deliberate: `TimeRange` carries a component id, so it would
// emit as a $ref and the sibling `default` would be dropped from the parameter.
export const SecurityRangeQuery = z.object({
  range: z.enum(TIME_RANGES).default(DEFAULT_TIME_RANGE),
});
export type SecurityRangeQuery = z.infer<typeof SecurityRangeQuery>;

// GET /v1/security/enforcement-actions
//
// Intercepted actions in the window, one entry per kind, with the period-over-
// period delta vs the immediately preceding window of equal length. Maps the
// finding `actionTaken` enum onto presentation-neutral kinds: block→blocked,
// redact→redacted, warn→warned (allow/log are not enforcement and excluded).
export const EnforcementActionKind = z
  .enum(['blocked', 'redacted', 'warned'])
  .meta({ id: 'EnforcementActionKind' });
export type EnforcementActionKind = z.infer<typeof EnforcementActionKind>;

export const EnforcementAction = z
  .object({
    kind: EnforcementActionKind,
    count: z.number().int().nonnegative(),
    // Signed change vs the preceding window of equal length.
    delta: z.number().int(),
  })
  .meta({ id: 'EnforcementAction' });
export type EnforcementAction = z.infer<typeof EnforcementAction>;

export const EnforcementActionsResponse = z
  .object({
    range: TimeRange,
    // Sum of actions[].count in the window.
    total: z.number().int().nonnegative(),
    // One entry per kind, always all three present (count may be 0).
    actions: z.array(EnforcementAction),
  })
  .meta({ id: 'EnforcementActionsResponse' });
export type EnforcementActionsResponse = z.infer<typeof EnforcementActionsResponse>;

// GET /v1/security/findings/timeseries
//
// New detections per bucket, split by severity. Granularity is server-chosen
// from the range (7d/30d → day; 3m/6m → week). Buckets with no findings are
// present with zeros. `low` is intentionally omitted (the chart plots
// critical/high/medium); add it if the widget grows a fourth series.
export const TimeseriesGranularity = z.enum(['day', 'week']).meta({ id: 'TimeseriesGranularity' });
export type TimeseriesGranularity = z.infer<typeof TimeseriesGranularity>;

export const FindingsTimeseriesPoint = z
  .object({
    // Bucket start, ISO-8601 date (YYYY-MM-DD). Ordered oldest → newest.
    timestamp: z.iso.date(),
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
  })
  .meta({ id: 'FindingsTimeseriesPoint' });
export type FindingsTimeseriesPoint = z.infer<typeof FindingsTimeseriesPoint>;

export const FindingsTimeseriesResponse = z
  .object({
    range: TimeRange,
    granularity: TimeseriesGranularity,
    points: z.array(FindingsTimeseriesPoint),
  })
  .meta({ id: 'FindingsTimeseriesResponse' });
export type FindingsTimeseriesResponse = z.infer<typeof FindingsTimeseriesResponse>;

// GET /v1/security/mttr-trend
//
// Mean time-to-remediate per bucket, split by severity. Granularity is
// server-chosen from the range (same day/week rule as findings/timeseries).
// A per-severity value is null when no `fixed-at-source` resolutions fell in
// that bucket for that severity (no data point to average, not zero).
export const MttrTrendPoint = z
  .object({
    // Bucket start, ISO-8601 date (YYYY-MM-DD). Ordered oldest → newest.
    timestamp: z.iso.date(),
    bySeverity: z.object({
      critical: z.number().nonnegative().nullable(),
      high: z.number().nonnegative().nullable(),
      medium: z.number().nonnegative().nullable(),
      low: z.number().nonnegative().nullable(),
    }),
  })
  .meta({ id: 'MttrTrendPoint' });
export type MttrTrendPoint = z.infer<typeof MttrTrendPoint>;

export const MttrTrendResponse = z
  .object({
    range: TimeRange,
    granularity: TimeseriesGranularity,
    points: z.array(MttrTrendPoint),
  })
  .meta({ id: 'MttrTrendResponse' });
export type MttrTrendResponse = z.infer<typeof MttrTrendResponse>;

// GET /v1/security/recently-resolved
//
// Most recent resolved findings, newest first. Semantic only — no labels;
// the frontend maps severity/path presentation.
export const ResolvedFeedItem = z
  .object({
    findingKey: z.string(),
    ruleId: z.string(),
    severity: Severity,
    path: z.string(),
    // ISO-8601 datetime (matches FindingInstance.detectedAt / the rest of the
    // findings domain). The reader `.toISOString()`s the DB epoch-ms values.
    resolvedAt: z.iso.datetime(),
    // ISO-8601 datetime; first-detection time for this finding.
    detectedAt: z.iso.datetime(),
  })
  .meta({ id: 'ResolvedFeedItem' });
export type ResolvedFeedItem = z.infer<typeof ResolvedFeedItem>;

export const RecentlyResolvedResponse = z
  .object({ items: z.array(ResolvedFeedItem) })
  .meta({ id: 'RecentlyResolvedResponse' });
export type RecentlyResolvedResponse = z.infer<typeof RecentlyResolvedResponse>;

// GET /v1/security/top-sources
//
// Repos & people ranked by findings in the window. `repo` sources come from
// events.metadata.repo; `user` sources from the event's userId (name resolved to
// the user's email via the catalog). Sorted by findingsCount desc.
// SOURCE_KINDS is the single source of values: SourceKind (with id) is echoed in
// the response, the query re-declares an inline enum from the same const so the
// two can't drift (and the query enum stays id-less to avoid a $ref-in-param).
export const SOURCE_KINDS = ['repo', 'user'] as const;
export const SourceKind = z.enum(SOURCE_KINDS).meta({ id: 'SourceKind' });
export type SourceKind = z.infer<typeof SourceKind>;

export const TopSource = z
  .object({
    // Stable id for linking to the source's detail view (e.g. `repo_payments-api`).
    id: z.string(),
    // Display name: repo slug, or the user's email.
    name: z.string(),
    kind: SourceKind,
    findingsCount: z.number().int().nonnegative(),
  })
  .meta({ id: 'TopSource' });
export type TopSource = z.infer<typeof TopSource>;

export const TopSourcesResponse = z
  .object({
    range: TimeRange,
    items: z.array(TopSource),
  })
  .meta({ id: 'TopSourcesResponse' });
export type TopSourcesResponse = z.infer<typeof TopSourcesResponse>;

export const TopSourcesQuery = z.object({
  range: z.enum(TIME_RANGES).default(DEFAULT_TIME_RANGE),
  limit: z.coerce.number().int().min(1).max(50).default(5),
  // Omit for both kinds.
  kind: z.enum(SOURCE_KINDS).optional(),
});
export type TopSourcesQuery = z.infer<typeof TopSourcesQuery>;

// GET /v1/security/scan-coverage
//
// Per-provider scan coverage. In the initial release only Claude Code is scanned;
// other providers are returned with supported:false (FE greys them out / "Soon").
// `provider` is its own stable id (note: `claudecode`, distinct from the event
// SourceTool `claude-code`). Uses the shared `range` query param.
// Order matches the dashboard display order (and SCAN_COVERAGE) so the generated
// OpenAPI enum list reads the same as the returned `providers` array.
export const Provider = z
  .enum(['claudecode', 'cursor', 'codex', 'chatgpt', 'copilot', 'api'])
  .meta({ id: 'Provider' });
export type Provider = z.infer<typeof Provider>;

export const ScanCoverageProvider = z
  .object({
    provider: Provider,
    // Percent of that provider's traffic scanned in the window. 0 when unsupported.
    coverage: z.number().int().min(0).max(100),
    supported: z.boolean(),
  })
  .meta({ id: 'ScanCoverageProvider' });
export type ScanCoverageProvider = z.infer<typeof ScanCoverageProvider>;

export const ScanCoverageResponse = z
  .object({
    range: TimeRange,
    providers: z.array(ScanCoverageProvider),
  })
  .meta({ id: 'ScanCoverageResponse' });
export type ScanCoverageResponse = z.infer<typeof ScanCoverageResponse>;

// GET /v1/security/recommended-actions (+ apply / dismiss)
//
// Prioritized, environment-specific suggestions. `category` and `action.type`
// are extensible enums kept as strings. The primary CTA has two modes: `apply`
// (server-side mutation, POST .../{id}/apply) or `navigate` (FE deep-links href).
export const SubjectType = z.enum(['repo', 'user', 'team', 'policy', 'share', 'rule']).meta({
  id: 'SubjectType',
});
export type SubjectType = z.infer<typeof SubjectType>;

export const RecommendationSubject = z
  .object({ type: SubjectType, id: z.string(), label: z.string() })
  .meta({ id: 'RecommendationSubject' });
export type RecommendationSubject = z.infer<typeof RecommendationSubject>;

export const RecommendationActionMode = z.enum(['apply', 'navigate']).meta({
  id: 'RecommendationActionMode',
});
export type RecommendationActionMode = z.infer<typeof RecommendationActionMode>;

export const RecommendationAction = z
  .object({
    mode: RecommendationActionMode,
    // Machine action key, e.g. promote_policy_to_block. Extensible.
    type: z.string(),
    label: z.string(),
    // Present when mode=navigate: in-app path the CTA links to.
    href: z.string().optional(),
    // Present when mode=apply: informational target ids (the apply endpoint
    // resolves the real target from the recommendation id, not these).
    policyId: z.string().optional(),
    teamId: z.string().optional(),
  })
  .meta({ id: 'RecommendationAction' });
export type RecommendationAction = z.infer<typeof RecommendationAction>;

export const RecommendedAction = z
  .object({
    id: z.string(),
    // Extensible (e.g. block_credentials, redact_pii, review_external_share).
    category: z.string(),
    severity: Severity,
    title: z.string(),
    description: z.string(),
    subjects: z.array(RecommendationSubject),
    action: RecommendationAction,
  })
  .meta({ id: 'RecommendedAction' });
export type RecommendedAction = z.infer<typeof RecommendedAction>;

export const RecommendedActionsResponse = z
  .object({ items: z.array(RecommendedAction) })
  .meta({ id: 'RecommendedActionsResponse' });
export type RecommendedActionsResponse = z.infer<typeof RecommendedActionsResponse>;

export const ListRecommendedActionsQuery = z.object({
  limit: z.coerce.number().int().min(1).max(20).default(3),
});
export type ListRecommendedActionsQuery = z.infer<typeof ListRecommendedActionsQuery>;

// Echo of the resolved action that was applied (type + target refs).
export const AppliedAction = z
  .object({
    type: z.string(),
    policyId: z.string().optional(),
    teamId: z.string().optional(),
  })
  .meta({ id: 'AppliedAction' });
export type AppliedAction = z.infer<typeof AppliedAction>;

export const ApplyRecommendedActionResponse = z
  .object({
    id: z.string(),
    status: z.literal('applied'),
    appliedAction: AppliedAction,
  })
  .meta({ id: 'ApplyRecommendedActionResponse' });
export type ApplyRecommendedActionResponse = z.infer<typeof ApplyRecommendedActionResponse>;

export const DismissRecommendedActionResponse = z
  .object({ id: z.string(), status: z.literal('dismissed') })
  .meta({ id: 'DismissRecommendedActionResponse' });
export type DismissRecommendedActionResponse = z.infer<typeof DismissRecommendedActionResponse>;

// Path param for the apply/dismiss routes. No component id — the generator
// expands path params inline (they cannot be a $ref).
export const RecommendedActionIdParam = z.object({ id: z.string() });
export type RecommendedActionIdParam = z.infer<typeof RecommendedActionIdParam>;
