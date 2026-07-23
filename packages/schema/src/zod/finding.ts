import { z } from 'zod';

// 'config' = configuration-posture rules (hook conflicts/egress — the config
// inventory surface). Their findings land in inspection_findings, not the
// legacy findings table, so toApiCategory never sees it today.
export const DetectionCategory = z
  .enum(['pii', 'financial', 'secret', 'phi', 'code_context', 'code_flaw', 'custom', 'config'])
  .meta({ id: 'DetectionCategory' });
export type DetectionCategory = z.infer<typeof DetectionCategory>;

export const Severity = z.enum(['critical', 'high', 'medium', 'low']).meta({ id: 'Severity' });
export type Severity = z.infer<typeof Severity>;

export const ActionTaken = z
  .enum(['warn', 'redact', 'block', 'allow', 'log'])
  .meta({ id: 'ActionTaken' });
export type ActionTaken = z.infer<typeof ActionTaken>;

// The enum members as a plain array, for callers that pre-fill a per-action map
// (e.g. healthSummary's byAction). Mirrors the `.enum(...)` order above.
export const ACTION_TAKEN_KEYS: readonly ActionTaken[] = ActionTaken.options;

export const Span = z
  .object({
    start: z.number().int().nonnegative(),
    end: z.number().int().nonnegative(),
  })
  .meta({ id: 'Span' });
export type Span = z.infer<typeof Span>;

// The canonical open-source finding shape AND the public OpenAPI component
// 'Finding'. Tenant-free — the public API contract carries no scoping columns.
// Consumed directly by @akasecurity/persistence and the OSS web-ui.
export const Finding = z
  .object({
    id: z.guid(),
    eventId: z.guid(),
    ruleId: z.string(),
    category: DetectionCategory,
    severity: Severity,
    span: Span,
    maskedMatch: z.string(),
    actionTaken: ActionTaken,
    confidence: z.number().min(0).max(1),
  })
  .meta({ id: 'Finding' });
export type Finding = z.infer<typeof Finding>;

// Detection produces a DetectedFinding. In OSS it equals the tenant-free Finding
// (ingest === stored); it keeps its own OpenAPI id.
export const DetectedFinding = Finding.meta({ id: 'DetectedFinding' });
export type DetectedFinding = z.infer<typeof DetectedFinding>;

// ─── API-facing enums (findings domain) ──────────────────────────────────────

// FindingAction: API-facing action enum. Maps from DB ActionTaken values at the
// boundary. 'monitored' is new (maps from DB 'log').
// 'quarantined' is RESERVED for a future enforcement action and has NO source in
// the current DB ActionTaken enum (warn|redact|block|allow|log) — so the boundary
// mappers (toApiAction/toDbAction) never produce or accept it today. It is in the
// enum for forward-compatibility only; it is system-assigned (clients may not send
// it — ApplyFindingActionRequest excludes it). When the quarantine enforcement
// action lands, ActionTaken gains a source value and the mappers wire it up.
export const FindingAction = z
  .enum(['blocked', 'redacted', 'warned', 'allowed', 'quarantined', 'monitored'])
  .meta({ id: 'FindingAction' });
export type FindingAction = z.infer<typeof FindingAction>;

// FindingProvider: API-facing provider enum. 'claudedesktop' is a new value
// (maps from source_tool = 'claude-desktop'). Never merged with 'claudecode'.
export const FindingProvider = z
  .enum(['claudecode', 'claudedesktop', 'cursor', 'copilot', 'chatgpt', 'api'])
  .meta({ id: 'FindingProvider' });
export type FindingProvider = z.infer<typeof FindingProvider>;

// FindingCategory: API-facing category enum. 'source_code' maps from DB
// 'code_context'; 'secret'/'pii' are 1:1; 'financial'/'phi'/'custom' pass
// through from the engine. 'external_share'/'mcp_server'/'customer_data' are
// part of the FE contract and accepted here for forward-compatibility — no
// detection rules emit them yet, so findings never carry them until those
// rules exist (separate detection-authoring work).
export const FindingCategory = z
  .enum([
    'secret',
    'pii',
    'source_code',
    'external_share',
    'mcp_server',
    'customer_data',
    'financial',
    'phi',
    'custom',
  ])
  .meta({ id: 'FindingCategory' });
export type FindingCategory = z.infer<typeof FindingCategory>;

// ─── Resolution / lifecycle enums (findings domain) ──────────────────────────

// FindingOrigin: where a finding was surfaced. 'in-flight' = intercepted as the
// event streamed through (an enforcement action could apply); 'at-rest' = found
// by scanning stored content after the fact (no in-flight enforcement possible).
export const FindingOrigin = z.enum(['in-flight', 'at-rest']).meta({ id: 'FindingOrigin' });
export type FindingOrigin = z.infer<typeof FindingOrigin>;

// FindingStatus: lifecycle state of a finding. 'open' is the default on creation;
// 'handled' = an in-flight enforcement action already contained it; 'resolved' =
// closed out (see ResolutionMethod for how); 'dismissed' = closed without action.
export const FindingStatus = z
  .enum(['open', 'handled', 'resolved', 'dismissed'])
  .meta({ id: 'FindingStatus' });
export type FindingStatus = z.infer<typeof FindingStatus>;

// ResolutionMethod: how a finding reached its current disposition (status).
// 'enforced-in-flight' = blocked/redacted/warned at the boundary; 'fixed-at-source'
// = the underlying content was remediated (no longer detected on re-scan);
// 'exception' = an approved policy exception covers it; 'acknowledged' = accepted
// risk without a fix; 'false-positive' = not a real finding; 'redetected' = a
// finding_key that was previously resolved (or otherwise handled) was detected
// again on a later scan — pairs with status 'open' to supersede the stale
// handled row and reassert the invariant that a currently-present finding_key
// is open, regardless of any past resolution (see resolutions.ts).
export const ResolutionMethod = z
  .enum([
    'enforced-in-flight',
    'fixed-at-source',
    'exception',
    'acknowledged',
    'false-positive',
    'redetected',
  ])
  .meta({ id: 'ResolutionMethod' });
export type ResolutionMethod = z.infer<typeof ResolutionMethod>;

// ─── Object shapes ────────────────────────────────────────────────────────────

export const FindingMatch = z
  .object({
    // Masked preview of the matched value. Never raw content.
    maskedValue: z.string(),
    // Redacted source-line prefix. Currently empty (pending privacy review).
    contextPrefix: z.string(),
  })
  .meta({ id: 'FindingMatch' });
export type FindingMatch = z.infer<typeof FindingMatch>;

export const FindingDetectionRef = z
  .object({
    id: z.string(),
    // Pack display name; null when the pack is not installed.
    name: z.string().nullable(),
  })
  .meta({ id: 'FindingDetectionRef' });
export type FindingDetectionRef = z.infer<typeof FindingDetectionRef>;

// FindingPolicyRef.name is REQUIRED (never null). The service synthesizes the
// name from the category at the service layer when no real policy name exists.
export const FindingPolicyRef = z
  .object({
    id: z.string(),
    name: z.string(),
  })
  .meta({ id: 'FindingPolicyRef' });
export type FindingPolicyRef = z.infer<typeof FindingPolicyRef>;

export const FindingInstance = z
  .object({
    id: z.string(),
    provider: FindingProvider,
    repo: z.string(),
    file: z.string(),
    // Host tool that produced the scanned text (event metadata's toolName).
    // Present whenever the capturing hook recorded one — including
    // file-attributed captures (views prefer `file`); its display value is
    // the location fallback ("via Bash") when no filePath exists. Absent for
    // legacy rows and non-tool captures (prompts, worktree scans).
    toolName: z.string().optional(),
    // Effective action: override.action ?? actionTaken, translated to FindingAction.
    action: FindingAction,
    detectedAt: z.iso.datetime(),
    confidence: z.number().min(0).max(1),
    // Lifecycle status (see FindingStatus). Optional so legacy callers/rows
    // that predate the resolution feature stay valid.
    status: FindingStatus.optional(),
  })
  .meta({ id: 'FindingInstance' });
export type FindingInstance = z.infer<typeof FindingInstance>;

export const FindingGroup = z
  .object({
    id: z.string(),
    category: FindingCategory,
    subtype: z.string(),
    severity: Severity,
    match: FindingMatch,
    detection: FindingDetectionRef,
    policy: FindingPolicyRef,
    instanceCount: z.number().int().nonnegative(),
    providers: z.array(FindingProvider),
    // Null when instances have differing actions (Mixed).
    aggregateAction: FindingAction.nullable(),
    latestDetectedAt: z.iso.datetime(),
    instances: z.array(FindingInstance),
    // Derived from instances' statuses with open-dominates precedence (see
    // buildFindingGroups). Undefined only when no instance carries a status.
    status: FindingStatus.optional(),
  })
  .meta({ id: 'FindingGroup' });
export type FindingGroup = z.infer<typeof FindingGroup>;

export const FindingStats = z
  .object({
    findings: z.number().int().nonnegative(),
    groups: z.number().int().nonnegative(),
    bySeverity: z.object({
      critical: z.number().int().nonnegative(),
      high: z.number().int().nonnegative(),
      medium: z.number().int().nonnegative(),
      low: z.number().int().nonnegative(),
    }),
  })
  .meta({ id: 'FindingStats' });
export type FindingStats = z.infer<typeof FindingStats>;

export const FindingFacetItem = z
  .object({
    value: z.string(),
    count: z.number().int().nonnegative(),
  })
  .meta({ id: 'FindingFacetItem' });
export type FindingFacetItem = z.infer<typeof FindingFacetItem>;

export const FindingFacets = z
  .object({
    // Each dimension computed excluding its own filter.
    severity: z.array(FindingFacetItem),
    subtype: z.array(FindingFacetItem),
    provider: z.array(FindingFacetItem),
    action: z.array(FindingFacetItem),
    // Counts by the group's derived status. The SQLite store derives a status
    // for every instance, so every group lands in a bucket; a status-less
    // group (possible only for callers whose rows carry no statuses) is
    // counted under no value.
    status: z.array(FindingFacetItem),
  })
  .meta({ id: 'FindingFacets' });
export type FindingFacets = z.infer<typeof FindingFacets>;

// ─── Request / response schemas ───────────────────────────────────────────────

// ListGroupedFindingsQuery / ListGroupedFindingsResponse: the grouped findings
// API (GET /v1/findings). Distinct from the legacy ListFindingsQuery in api.ts
// which backs the old simple list.
//
// Query schema — intentionally NO `.meta({ id })`: the OpenAPI generator expands
// query params into individual `parameters` (which cannot be a `$ref`), so it
// must stay inline (see api.ts header). `limit` uses `z.coerce.number()` because
// query params arrive as strings (`?limit=50`).
// Default page size for grouped findings when the query omits `limit` (schema
// caps `limit` at 100). Shared by every findings read path so all consumers
// page identically — a single source of
// truth rather than each consumer inventing its own default.
export const DEFAULT_GROUPED_FINDINGS_LIMIT = 50;

export const ListGroupedFindingsQuery = z.object({
  // NOTE: severity filters by Severity (critical/high/medium/low), not by
  // FindingAction.
  severity: z.array(Severity).optional(),
  subtype: z.array(z.string()).optional(),
  provider: z.array(FindingProvider).optional(),
  action: z.array(FindingAction).optional(),
  // Matches a group's DERIVED status (see FindingGroup.status), not its
  // individual instances' — so a filtered group's Status column always reads
  // one of the requested values.
  status: z.array(FindingStatus).optional(),
  q: z.string().optional(),
  // Scope to findings whose event carries this session id (the Activity page's
  // session → findings drilldown). Findings without a session never match.
  sessionId: z.string().optional(),
  groupBy: z.literal('type').optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  cursor: z.string().optional(),
});
export type ListGroupedFindingsQuery = z.infer<typeof ListGroupedFindingsQuery>;

export const ListGroupedFindingsResponse = z
  .object({
    totals: z.object({
      findings: z.number().int().nonnegative(),
      groups: z.number().int().nonnegative(),
    }),
    facets: FindingFacets,
    items: z.array(FindingGroup),
    nextCursor: z.string().nullable(),
    // Present only on session-scoped queries (`sessionId` set): per ruleId, how
    // many times that rule fired in the session's persisted transcript. Findings
    // here are deduplicated to unique values while the transcript tally counts
    // every firing, so the two numbers legitimately differ — this map lets a
    // session-scoped view show both.
    sessionFirings: z.record(z.string(), z.number().int().nonnegative()).optional(),
  })
  .meta({ id: 'ListGroupedFindingsResponse' });
export type ListGroupedFindingsResponse = z.infer<typeof ListGroupedFindingsResponse>;

export const ApplyFindingActionRequest = z
  .object({
    // 'quarantined' is system-assigned (see FindingAction) — clients may not set
    // it, so it is excluded from the request contract. The mapping helper
    // (toDbAction) also throws on it as defence-in-depth.
    action: FindingAction.exclude(['quarantined']),
    instanceId: z.string().optional(),
  })
  .meta({ id: 'ApplyFindingActionRequest' });
export type ApplyFindingActionRequest = z.infer<typeof ApplyFindingActionRequest>;

// ApplyFindingActionResponse is the same shape as FindingGroup (updated group).
export const ApplyFindingActionResponse = FindingGroup.meta({ id: 'ApplyFindingActionResponse' });
export type ApplyFindingActionResponse = z.infer<typeof ApplyFindingActionResponse>;

// ExportFindingsQuery: same filter params as ListFindingsQuery minus pagination.
// Query schema — NO `.meta({ id })` (see ListGroupedFindingsQuery / api.ts header).
export const ExportFindingsQuery = z.object({
  severity: z.array(Severity).optional(),
  subtype: z.array(z.string()).optional(),
  provider: z.array(FindingProvider).optional(),
  action: z.array(FindingAction).optional(),
  q: z.string().optional(),
  format: z.enum(['csv', 'json']).optional(),
});
export type ExportFindingsQuery = z.infer<typeof ExportFindingsQuery>;

// FindingInstanceDetail: denormalized instance detail combining FindingInstance
// fields with group-level context. Returned by GET /v1/findings/instances/:id.
export const FindingInstanceDetail = FindingInstance.extend({
  groupId: z.string(),
  category: FindingCategory,
  subtype: z.string(),
  severity: Severity,
  match: FindingMatch,
  detection: FindingDetectionRef,
  policy: FindingPolicyRef,
}).meta({ id: 'FindingInstanceDetail' });
export type FindingInstanceDetail = z.infer<typeof FindingInstanceDetail>;
