// Persistence ports — the async read/view contracts the SQLite adapter (this
// package) satisfies, so read code (the web-ui, the CLI) is written once
// against the interface rather than a concrete repository. They are async so
// an adapter over an async driver could satisfy them too; the SQLite adapter
// fulfils them by wrapping synchronous node:sqlite results in Promise.resolve.
//
// WRITES are deliberately NOT on these ports. They go through the LocalDatabase
// facade, which owns its own transaction/atomicity semantics — keeping writes
// off the shared port is what lets recordCapture stay a single synchronous
// transaction (see database.ts).
//
// The composite "view" ports (DashboardViews) are read aggregations independent
// of the entity row shapes — the dashboards read these.
import type {
  ActivitySession,
  AssetDetail,
  DayActivity,
  DetectionDetail,
  DetectionStats,
  EnforcementActionsResponse,
  FileDetail,
  FindingsTimeseriesResponse,
  FindingView,
  GetActivityStatsResponse,
  GetProjectTreeQuery,
  Harness,
  HealthSummary,
  InventoryStats,
  ListActivitySessionsQuery,
  ListActivitySessionsResponse,
  ListAssetsQuery,
  ListAssetsResponse,
  ListDetectionsQuery,
  ListDetectionsResponse,
  ListGroupedFindingsQuery,
  ListGroupedFindingsResponse,
  ListHarnessesResponse,
  ListPoliciesResponse,
  ListProjectsResponse,
  ListShareDestinationsQuery,
  ListShareDestinationsResponse,
  MttrTrendResponse,
  NeedsReviewResponse,
  Policy,
  PolicyDetail,
  PolicyKind,
  PolicyStatsResponse,
  ProjectTreeResponse,
  RecentlyResolvedResponse,
  ScanCoverageResponse,
  SecurityRange,
  SessionTokenReport,
  SeveritySummaryResponse,
  ShareDestinationDetail,
  SharesStats,
  SourceKind,
  TopSourcesResponse,
} from '@akasecurity/schema';

import type { InstalledPackCounts } from './repositories/installed-packs.ts';

export interface EventsReadPort {
  /** Every recorded content hash for the local store — backfill dedup. */
  contentHashes(): Promise<Set<string>>;
}

export interface FindingsReadPort {
  recentFindings(opts?: { limit?: number }): Promise<FindingView[]>;
}

/**
 * Grouped findings read. Groups findings by ruleId (with per-filter-excluded
 * facets) into the same @akasecurity/schema response the dashboards consume, so the
 * Findings page renders identically across surfaces. Not on the shared
 * FindingsReadPort, so a read-only adapter is not forced to implement it — the
 * local store IS the findings service. No overrides / pack names / cursor.
 */
export interface GroupedFindingsView {
  listGroupedFindings(query: ListGroupedFindingsQuery): Promise<ListGroupedFindingsResponse>;
}

/** Aggregated dashboard reads — independent of the findings row shape. */
export interface DashboardViews {
  healthSummary(): Promise<HealthSummary>;
  activityByDay(days?: number): Promise<DayActivity[]>;
}

export interface PoliciesReadPort {
  readPolicies(): Promise<Policy[]>;
}

/**
 * Policies page reads — the built-in policy catalog (monitor/warn/redact/
 * block) with live "used by N detections" counts over installed_packs. The
 * SQLite adapter both reads AND assembles the finished @akasecurity/schema responses
 * from the shared BUILTIN_POLICIES catalog, so dashboards render identically.
 * Separate from PoliciesReadPort, which
 * serves the raw enforcement `Policy[]` bundle — this port is the read-catalog for
 * the page, not the enforcement rows.
 */
export interface PolicyCatalogReadPort {
  getPolicyList(kind?: PolicyKind): Promise<ListPoliciesResponse>;
  getPolicyStats(): Promise<PolicyStatsResponse>;
  getPolicyDetail(id: string): Promise<PolicyDetail | null>;
}

export interface InstalledPacksReadPort {
  counts(): Promise<InstalledPackCounts>;
}

/**
 * Detections read views over installed_packs (+ findings for the 30-day
 * count). The SQLite adapter reads AND shapes here — the local store IS the
 * detections service. It has no rule registry, so `update` is always null and
 * the `updates` filter is always empty. Reuses the pure @akasecurity/schema builders
 * (buildDetectionsList / rowToDetectionDetail) so the shapes never drift from
 * the published contract. Not on a cross-adapter port, like GroupedFindingsView
 * / SecurityViews.
 */
export interface DetectionsReadPort {
  listDetections(query: ListDetectionsQuery): Promise<ListDetectionsResponse>;
  /** Full detail for "namespace/packId"; null when the pack is not installed. */
  getDetectionDetail(id: string): Promise<DetectionDetail | null>;
  getDetectionStats(): Promise<DetectionStats>;
}

/**
 * Security dashboard read views — range-driven aggregations over findings (joined
 * to their parent event for the timestamp/repo). Returns the finished
 * @akasecurity/schema response shapes the security widget views consume.
 *
 * The SQLite adapter fetches AND aggregates behind this port, so a single call
 * gives the web-ui / CLI the response — the local store IS the security service.
 * `severitySummary` is whole-store (not range-scoped), matching the contract.
 */
export interface SecurityViews {
  severitySummary(): Promise<SeveritySummaryResponse>;
  enforcementActions(range: SecurityRange): Promise<EnforcementActionsResponse>;
  findingsTimeseries(range: SecurityRange): Promise<FindingsTimeseriesResponse>;
  mttrTrend(range: SecurityRange): Promise<MttrTrendResponse>;
  topSources(
    range: SecurityRange,
    opts?: { limit?: number; kind?: SourceKind },
  ): Promise<TopSourcesResponse>;
  scanCoverage(range: SecurityRange): Promise<ScanCoverageResponse>;
  recentlyResolved(limit?: number): Promise<RecentlyResolvedResponse>;
}

/**
 * Data Shares read views over the tenant-free local store (share_destination
 * / endpoint / call_site + egress_decision_override). Like SecurityViews /
 * DetectionsReadPort, the SQLite adapter both fetches AND assembles the
 * finished @akasecurity/schema responses (grouped register, needs-review strip,
 * destination detail, stats), so the Data Shares page renders identically
 * across surfaces — the local store IS the shares service. Not on a
 * cross-adapter port. The egress-decision WRITE lives off this port on the
 * concrete repository (SqliteSharesRepository.setEgressDecision), like how
 * installed-pack edits stay off InstalledPacksReadPort.
 */
export interface SharesReadPort {
  stats(): Promise<SharesStats>;
  listDestinations(query: ListShareDestinationsQuery): Promise<ListShareDestinationsResponse>;
  needsReview(): Promise<NeedsReviewResponse>;
  getDestination(destinationId: string): Promise<ShareDestinationDetail | null>;
}

/**
 * Inventory read views over the tenant-free local store — the asset model
 * (inventory_asset / harness_asset / project_file + their overrides) plus the
 * shared inventory (harnesses) / source_project (projects) tables. Like the other
 * view ports, the SQLite adapter both fetches AND assembles the finished
 * @akasecurity/schema responses, so the Inventory page renders identically across
 * surfaces. The file-access / MCP-trust writes live off this port on the
 * concrete repository.
 * `getProjectTree`/`getProjectFile` return null for an unknown project/harness
 * (the route/page maps that to a not-found).
 *
 * There is no harness-events read here: the local model has no enforcement-event
 * source yet, so the HarnessOverview "recent blocks" list is a fixed empty
 * constant the page passes directly (no port method pretending to be a live
 * query). Add it back when a real scanner records events.
 */
export interface InventoryReadPort {
  getInventoryStats(): Promise<InventoryStats>;
  listHarnesses(q?: string): Promise<ListHarnessesResponse>;
  listAssets(query: ListAssetsQuery): Promise<ListAssetsResponse>;
  listProjects(q?: string): Promise<ListProjectsResponse>;
  getAsset(assetId: string): Promise<AssetDetail | null>;
  getProjectTree(
    projectId: string,
    query: GetProjectTreeQuery,
  ): Promise<ProjectTreeResponse | null>;
  getProjectFile(projectId: string, path: string): Promise<FileDetail | null>;
}

/**
 * Activity read views over the tenant-free local `audit_events` store —
 * sessions reconstructed from the session/tool-call/llm-call timeline. Like
 * SecurityViews / SharesReadPort, the SQLite adapter both fetches AND
 * assembles the finished @akasecurity/schema responses (today stats · session list ·
 * session detail with embedded timeline), so the Activity page renders
 * identically across surfaces — the local store IS the activity service.
 * Not on a cross-adapter port.
 *
 * Single-tenant: no tenant/user predicate on any query. A session is any
 * `event_type='session'` root; a row missing the (not-yet-live-written) rich
 * attributes degrades to defensive defaults (harness → `claudecode`, empty
 * title, …) rather than being hidden, so dashboards render identically for
 * bare rows too. `getSession` returns null for an unknown id (the page maps
 * that to an empty pane / not-found), like `getDestination`/`getAsset`.
 */
export interface ActivityReadPort {
  stats(tz?: string): Promise<GetActivityStatsResponse>;
  listSessions(query: ListActivitySessionsQuery): Promise<ListActivitySessionsResponse>;
  getSession(sessionId: string): Promise<ActivitySession | null>;
  // Token-usage reports over the `llm_call` leaves, cost DERIVED at read time.
  // `tokenReports(fromMs?)` scopes to a `started_at >= fromMs` window (the
  // Activity page's range) or all-time; `tokenReportForSession` is the single-
  // session breakdown for the detail pane. The caller collapses reports onto
  // per-model rows via `aggregateTokenUsage`.
  tokenReports(fromMs?: number): Promise<SessionTokenReport[]>;
  tokenReportForSession(sessionId: string): Promise<SessionTokenReport | null>;
  // The harnesses that actually have sessions (optionally within `fromMs`), so
  // the filter only offers present harnesses rather than the whole enum.
  harnessFacets(fromMs?: number): Promise<Harness[]>;
}
