// Activity API (`/v1/activity`) — contracts. Self-scoped
// endpoints backing the dashboard Activity page: today stats, a flat session
// list, session detail with an embedded audit timeline, a paginated events
// escape hatch, the raw pre-reconstruction log, an export, and a composite
// overview. Responses are SEMANTIC, not presentational — no color/icon/day/
// fill/tone/dot fields and no pre-formatted strings; the frontend maps those
// from the enums/counts below. No shape here carries user or tenancy scoping
// fields (service method params only).
import { z } from 'zod';

import { Severity } from './finding.ts';
import { Harness } from './harness-map.ts';
import { TokenRollup } from './meta.ts';

// Re-exported for convenience — Activity reuses harness-map's `Harness` and
// finding's `Severity` verbatim (identical shapes); do not redeclare either
// under a new id. `Severity` is re-exported as `eventSeverity` to match the
// contract's shared enum vocabulary while staying the exact same
// schema/component — no locally redefined severity set.
export { Harness };
export { Severity as eventSeverity };

// ─── Enums ────────────────────────────────────────────────────────────────────

export const SessionStatus = z.enum(['active', 'completed', 'interrupted', 'error']);
export type SessionStatus = z.infer<typeof SessionStatus>;

export const AuditEventKind = z.enum([
  'session',
  'prompt',
  'response',
  'tool',
  'hook',
  'detection',
  'share',
  'permission',
  'commit',
  'error',
  'active',
]);
export type AuditEventKind = z.infer<typeof AuditEventKind>;

/** Which surface an event cross-links to. Paired with `targetId`; FE composes
 * the "Open in …" link client-side — the API returns only the enum + id. */
export const ActivityLink = z.enum(['detections', 'shares', 'inventory']);
export type ActivityLink = z.infer<typeof ActivityLink>;

// ─── Shape: AuditEvent ────────────────────────────────────────────────────────

/** One entry on a session's audit timeline. `tool`/`severity`/`link`/`targetId`
 * are `null` when absent (never omitted or empty string — see spec "Event
 * optional fields are null when absent"). `internal`/`flagged` are always
 * present booleans (never omitted), defaulting false when the underlying
 * event carries neither badge.
 *
 * `.meta({id})` uses the scoped id `'ActivityAuditEvent'`, not `'AuditEvent'`:
 * this library derives `<id>Input` component keys, and `'AuditEvent' + 'Input'`
 * would collide with meta.ts's existing `AuditEventInput` component. The plain
 * domain name stays the exported TS identifier (mirrors the shares.ts
 * `ShareTrustLevel` precedent). */
export const AuditEvent = z
  .object({
    id: z.string(),
    occurredAt: z.iso.datetime(),
    kind: AuditEventKind,
    title: z.string(),
    detail: z.string(),
    /** Present on `tool` events (`Bash`, `Edit`, `Read`…); null otherwise. */
    tool: z.string().nullable(),
    /** Present on `detection`/`permission`/`error`/flagged `share` events. */
    severity: Severity.nullable(),
    link: ActivityLink.nullable(),
    /** Id on the linked surface (findingId / shareId / assetId); null when `link` is null. */
    targetId: z.string().nullable(),
    /** `share` to a first-party/internal destination. */
    internal: z.boolean(),
    /** Event needs review (e.g. unverified egress). */
    flagged: z.boolean(),
  })
  .meta({ id: 'ActivityAuditEvent' });
export type AuditEvent = z.infer<typeof AuditEvent>;

// ─── Shape: ActivitySessionSummary ────────────────────────────────────────────

// `.meta({id})` is added here because `GET /v1/activity/sessions` now
// references this shape directly (embedded in ListActivitySessionsResponse) —
// OpenAPI-component registration happens only once a route actually wires a
// shape, to avoid leaking orphan components.
export const ActivitySessionSummary = z
  .object({
    id: z.string(),
    harness: Harness,
    title: z.string(),
    project: z.string(),
    repo: z.string(),
    /** Branches touched, primary first. */
    branches: z.array(z.string()),
    startedAt: z.iso.datetime(),
    /** `null` while `status: "active"`. */
    endedAt: z.iso.datetime().nullable(),
    status: SessionStatus,
    turns: z.number().int().nonnegative(),
    /** Detections triggered in the session. */
    findings: z.number().int().nonnegative(),
    /** Egress destinations in the session. */
    shares: z.number().int().nonnegative(),
  })
  .meta({ id: 'ActivitySessionSummary' });
export type ActivitySessionSummary = z.infer<typeof ActivitySessionSummary>;

// ─── Shape: ActivitySession ────────────────────────────────────────────────────

/**
 * Session detail = the session-summary fields plus the detail-only fields
 * below, with the session's full audit timeline embedded in `events`. A
 * separate events endpoint (`GET /v1/activity/sessions/{sessionId}/events`)
 * returns the same timeline ordered and paginated, for callers that want to
 * page through it instead of consuming the full embed.
 *
 * `tokens` reuses the shared `TokenRollup` (meta.ts) verbatim — no locally
 * duplicated token shape (spec "tokens shape matches TokenRollup"). Two field
 * mapping decisions:
 *   1. Field names: the source data's shorthand field names (`input`/`output`)
 *      maps onto TokenRollup's `inputTokens`/`outputTokens`; `cacheRead`/
 *      `cacheCreation` already match verbatim. The FE reads the TokenRollup
 *      field names directly — this is NOT a re-shorthanding at the API layer.
 *   2. `TokenRollup.sessionId`/`model`/`provider` don't have one natural value
 *      for a session that used multiple models (`models: string[]` below):
 *      `sessionId` = the root session id; `model`/`provider` = the primary/
 *      first model of the session (the first `llm_call` leaf chronologically);
 *      `estimatedCostUsd` is null this milestone until a price map is wired.
 *
 * `GET /v1/activity/sessions/{sessionId}` references this shape directly —
 * `.meta({id})` registers it as an OpenAPI component.
 */
export const ActivitySession = ActivitySessionSummary.extend({
  /** Machine the session ran on — the page subtitle host. */
  host: z.string(),
  /** Working directory (the session root; single value). */
  cwd: z.string(),
  /** Models used — a run can switch models / spawn subagents mid-session. */
  models: z.array(z.string()),
  /** Harness/CLI version string. */
  version: z.string(),
  tokens: TokenRollup,
  /** Per-tool call counts, keyed by tool name. */
  tools: z.record(z.string(), z.number().int().nonnegative()),
  files: z.array(z.string()),
  commits: z.number().int().nonnegative(),
  /** Audit timeline, oldest → newest. */
  events: z.array(AuditEvent),
}).meta({ id: 'ActivitySession' });
export type ActivitySession = z.infer<typeof ActivitySession>;

// ─── getActivityStats ──────────────────────────────────────────────────────────
// Query schema intentionally carries NO `.meta({ id })`: the OpenAPI generator
// expands query params into individual `parameters` (which cannot be a `$ref`),
// so it must stay inline. See shares.ts / inventory.ts header for the same rule.

/** GET /v1/activity/stats query params. `tz` defines the "today" boundary;
 * omitted defaults to the account timezone (resolved server-side). */
export const GetActivityStatsQuery = z.object({
  tz: z.string().optional(),
});
export type GetActivityStatsQuery = z.infer<typeof GetActivityStatsQuery>;

// `.meta({id})` is added here because `GET /v1/activity/stats` now references
// this shape directly — OpenAPI-component registration happens only once a
// route actually wires a shape, to avoid leaking orphan components.
export const GetActivityStatsResponse = z
  .object({
    sessionsToday: z.number().int().nonnegative(),
    liveNow: z.number().int().nonnegative(),
    toolCallsToday: z.number().int().nonnegative(),
    findingsToday: z.number().int().nonnegative(),
    egressToday: z.number().int().nonnegative(),
  })
  .meta({ id: 'GetActivityStatsResponse' });
export type GetActivityStatsResponse = z.infer<typeof GetActivityStatsResponse>;

// ─── listActivitySessions ──────────────────────────────────────────────────────

/** GET /v1/activity/sessions query params. No boolean params exist here today
 * — if one is ever added it MUST use `z.stringbool()`, never
 * `z.coerce.boolean()` (`Boolean(str)` is true for any non-empty string, so
 * `?flag=false`/`?flag=0` would wrongly coerce to `true` — see shares.ts). */
export const ListActivitySessionsQuery = z.object({
  /** Case-insensitive match over session title/project/branches AND event title/detail (server-side). */
  q: z.string().optional(),
  /** Repeatable multi-select. Restrict to these harness ids; omitted = all harnesses. */
  harness: z.array(Harness).optional(),
  /** Lower bound on startedAt. */
  from: z.union([z.iso.date(), z.iso.datetime()]).optional(),
  /** Upper bound on startedAt; omitted defaults to now. */
  to: z.union([z.iso.date(), z.iso.datetime()]).optional(),
  /** Page size, 1–100; out-of-range values are a 400. `z.coerce` — query params arrive as strings. */
  limit: z.coerce.number().int().min(1).max(100).default(50),
  /** Opaque pagination cursor (most-recent first). */
  cursor: z.string().optional(),
});
export type ListActivitySessionsQuery = z.infer<typeof ListActivitySessionsQuery>;

export const ListActivitySessionsResponse = z
  .object({
    items: z.array(ActivitySessionSummary),
    /** `null` once the last page is reached. */
    nextCursor: z.string().nullable(),
  })
  .meta({ id: 'ListActivitySessionsResponse' });
export type ListActivitySessionsResponse = z.infer<typeof ListActivitySessionsResponse>;

// ─── getActivitySession ─────────────────────────────────────────────────────────

/** GET /v1/activity/sessions/{sessionId} has no query params — the response is
 * exactly `ActivitySession` (no wrapper). Aliased for Query/Response naming
 * symmetry with the other endpoints; NOT a distinct OpenAPI component (same
 * schema object/id as `ActivitySession` — reusing it here, not redefining). */
export const GetActivitySessionResponse = ActivitySession;
export type GetActivitySessionResponse = ActivitySession;

// ─── listSessionEvents (pagination escape hatch) ────────────────────────────────

/** GET /v1/activity/sessions/{sessionId}/events query params. */
export const ListSessionEventsQuery = z.object({
  /** Default 100, range 1–500. */
  limit: z.coerce.number().int().min(1).max(500).default(100),
  cursor: z.string().optional(),
  /** Reorders without changing the item set. */
  order: z.enum(['asc', 'desc']).default('asc'),
});
export type ListSessionEventsQuery = z.infer<typeof ListSessionEventsQuery>;

// `.meta({id})` is added here because `GET /v1/activity/sessions/{sessionId}/events`
// now references this shape directly — OpenAPI-component registration happens
// only once a route actually wires a shape, to avoid leaking orphan components.
export const ListSessionEventsResponse = z
  .object({
    items: z.array(AuditEvent),
    nextCursor: z.string().nullable(),
  })
  .meta({ id: 'ListSessionEventsResponse' });
export type ListSessionEventsResponse = z.infer<typeof ListSessionEventsResponse>;

// ─── getSessionRawLog ────────────────────────────────────────────────────────────

/** GET /v1/activity/sessions/{sessionId}/raw query params. The 200 response is
 * a stream (`application/x-ndjson` default, or `{records:[...]}` with
 * `format=json`), not a single JSON schema — no `.meta({id})` Response shape
 * here; the streaming raw-log route models directly against `AuditEventInput`
 * (meta.ts), the raw pre-reconstruction record shape. */
export const GetSessionRawLogQuery = z.object({
  format: z.enum(['ndjson', 'json']).default('ndjson'),
});
export type GetSessionRawLogQuery = z.infer<typeof GetSessionRawLogQuery>;

// ─── exportActivity ──────────────────────────────────────────────────────────────

/** GET /v1/activity/export query params — the session-list filters plus `format`. The 200
 * response is a file download (`text/csv` or `application/json` with
 * `Content-Disposition: attachment`), not a single JSON schema — no
 * `.meta({id})` Response shape here. */
export const ExportActivityQuery = z.object({
  format: z.enum(['csv', 'json']).default('csv'),
  q: z.string().optional(),
  harness: z.array(Harness).optional(),
  from: z.union([z.iso.date(), z.iso.datetime()]).optional(),
  to: z.union([z.iso.date(), z.iso.datetime()]).optional(),
});
export type ExportActivityQuery = z.infer<typeof ExportActivityQuery>;

// ─── /overview: getActivityOverview ───────────────────────────────────────────

/** GET /v1/activity/overview — a fan-out convenience for initial paint: the
 * bodies of the stats and session-list endpoints with default filters, not
 * an independent query path.
 *
 * `.meta({id})` is added here because `GET /v1/activity/overview` now
 * references this shape directly — OpenAPI-component registration happens
 * only once a route actually wires a shape, to avoid leaking orphan
 * components (same rule every other response shape in this file follows). */
export const ActivityOverviewResponse = z
  .object({
    stats: GetActivityStatsResponse,
    sessions: ListActivitySessionsResponse,
  })
  .meta({ id: 'ActivityOverviewResponse' });
export type ActivityOverviewResponse = z.infer<typeof ActivityOverviewResponse>;
