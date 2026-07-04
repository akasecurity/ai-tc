import { z } from 'zod';

import { RescanResponse } from './inventory.ts';

// Re-exported for convenience — shares reuses inventory's RescanResponse verbatim
// (identical `{jobId,startedAt}` shape); do not redeclare it under a new id.
export { RescanResponse };

// ─── Enums ────────────────────────────────────────────────────────────────────

export const DestinationKind = z
  .enum(['provider', 'internal', 'ip'])
  .meta({ id: 'DestinationKind' });
export type DestinationKind = z.infer<typeof DestinationKind>;

export const Transport = z
  .enum(['https', 'http', 'sftp', 'grpc', 'smtp'])
  .meta({ id: 'Transport' });
export type Transport = z.infer<typeof Transport>;

/** Listed most-sensitive → least; this order drives `topDataClass` and `dataClasses` sort. */
export const DataClass = z
  .enum(['secrets', 'pii', 'customer', 'source', 'telemetry', 'logs', 'metrics', 'none'])
  .meta({ id: 'DataClass' });
export type DataClass = z.infer<typeof DataClass>;

/** Sensitivity ranking, most-sensitive first — matches DataClass's declaration order. */
export const DATA_CLASS_ORDER = DataClass.options;

/**
 * Derived, read-only egress trust posture. Renamed from `TrustLevel` to avoid
 * collision with inventory.ts's existing `TrustLevel` (known-good/risky/unapproved).
 * OpenAPI component id: 'ShareTrustLevel'.
 */
export const ShareTrustLevel = z
  .enum(['recognized', 'internal', 'unverified', 'ip'])
  .meta({ id: 'ShareTrustLevel' });
export type ShareTrustLevel = z.infer<typeof ShareTrustLevel>;

export const EgressDecision = z.enum(['allow', 'block']).meta({ id: 'EgressDecision' });
export type EgressDecision = z.infer<typeof EgressDecision>;

export const EgressStatus = z.enum(['allowed', 'blocked', 'review']).meta({ id: 'EgressStatus' });
export type EgressStatus = z.infer<typeof EgressStatus>;

export const ReviewReason = z
  .enum(['raw_ip', 'unverified_domain', 'plaintext_transport'])
  .meta({ id: 'ReviewReason' });
export type ReviewReason = z.infer<typeof ReviewReason>;

export const HttpMethod = z.enum(['GET', 'POST', 'PUT', 'DELETE']).meta({ id: 'HttpMethod' });
export type HttpMethod = z.infer<typeof HttpMethod>;

// ─── Shared sub-shapes ────────────────────────────────────────────────────────

/** Reused across ShareDestinationSummary, ShareDestinationDetail, ReviewDestination. */
export const ReviewInfo = z
  .object({
    needsReview: z.boolean(),
    reasons: z.array(ReviewReason),
  })
  .meta({ id: 'ReviewInfo' });
export type ReviewInfo = z.infer<typeof ReviewInfo>;

/** Non-provider hosts only — `geo`/`ptr` are resolver strings; null for providers. */
export const DestinationNetwork = z
  .object({
    port: z.number().int().nullable(),
    geo: z.string().nullable(),
    ptr: z.string().nullable(),
  })
  .meta({ id: 'DestinationNetwork' });
export type DestinationNetwork = z.infer<typeof DestinationNetwork>;

// ─── Shape 1: EndpointSummary ─────────────────────────────────────────────────

export const EndpointSummary = z
  .object({
    id: z.string(),
    method: HttpMethod,
    transport: Transport,
    url: z.string(),
    template: z.boolean(),
    dataClass: DataClass,
    lastSeen: z.iso.datetime(),
    callSiteCount: z.number().int().nonnegative(),
  })
  .meta({ id: 'EndpointSummary' });
export type EndpointSummary = z.infer<typeof EndpointSummary>;

// ─── Shape 2: CallSite ────────────────────────────────────────────────────────

export const CallSite = z
  .object({
    id: z.string(),
    project: z.string(),
    file: z.string(),
    line: z.number().int().nonnegative(),
    snippet: z.string(),
    dynamic: z.boolean(),
    vendored: z.boolean(),
    /** Deep-link to the Inventory project, when the repo is governed there. */
    projectId: z.string().nullable(),
  })
  .meta({ id: 'CallSite' });
export type CallSite = z.infer<typeof CallSite>;

// ─── Shape 3: EndpointWithSites ───────────────────────────────────────────────

/** EndpointSummary plus embedded call sites (destination detail only). */
export const EndpointWithSites = EndpointSummary.extend({
  sites: z.array(CallSite),
}).meta({ id: 'EndpointWithSites' });
export type EndpointWithSites = z.infer<typeof EndpointWithSites>;

// ─── Shape 4: ShareDestinationSummary ─────────────────────────────────────────

/** Grouped register row — endpoints embedded (no call sites). */
export const ShareDestinationSummary = z
  .object({
    id: z.string(),
    kind: DestinationKind,
    name: z.string(),
    host: z.string(),
    category: z.string(),
    trust: ShareTrustLevel,
    /** Effective state (decision applied over the trust default). */
    status: EgressStatus,
    /** True when an egress decision override differs from the trust default. */
    isCustom: z.boolean(),
    lastSeen: z.iso.datetime(),
    endpointCount: z.number().int().nonnegative(),
    callSiteCount: z.number().int().nonnegative(),
    transports: z.array(Transport),
    /** Most-sensitive first. */
    dataClasses: z.array(DataClass),
    review: ReviewInfo,
    /** Non-provider hosts only; null for providers. */
    network: DestinationNetwork.nullable(),
    /** Embedded for inline expansion — no call sites here. */
    endpoints: z.array(EndpointSummary),
  })
  .meta({ id: 'ShareDestinationSummary' });
export type ShareDestinationSummary = z.infer<typeof ShareDestinationSummary>;

// ─── Shape 5: ShareDestinationDetail ──────────────────────────────────────────

/** Destination detail: full endpoints with embedded call sites, plus note. */
export const ShareDestinationDetail = ShareDestinationSummary.omit({
  endpointCount: true,
  callSiteCount: true,
  endpoints: true,
})
  .extend({
    /** Ownership/geo rationale; null for providers. */
    note: z.string().nullable(),
    endpoints: z.array(EndpointWithSites),
  })
  .meta({ id: 'ShareDestinationDetail' });
export type ShareDestinationDetail = z.infer<typeof ShareDestinationDetail>;

// ─── Shape 6: ReviewDestination ───────────────────────────────────────────────

/** Trimmed destination summary for the needs-review strip. */
export const ReviewDestination = z
  .object({
    id: z.string(),
    kind: DestinationKind,
    name: z.string(),
    trust: ShareTrustLevel,
    status: EgressStatus,
    review: ReviewInfo,
    topDataClass: DataClass,
    callSiteCount: z.number().int().nonnegative(),
    lastSeen: z.iso.datetime(),
  })
  .meta({ id: 'ReviewDestination' });
export type ReviewDestination = z.infer<typeof ReviewDestination>;

// ─── Shape 7: ShareDestinationGroup ───────────────────────────────────────────

export const ShareDestinationGroup = z
  .object({
    kind: DestinationKind,
    total: z.number().int().nonnegative(),
    items: z.array(ShareDestinationSummary),
  })
  .meta({ id: 'ShareDestinationGroup' });
export type ShareDestinationGroup = z.infer<typeof ShareDestinationGroup>;

// ─── Shape 8: ListShareDestinationsResponse ──────────────────────────────────

/** Grouped branch — `groups` ordered provider → internal → ip. */
export const ListShareDestinationsResponse = z
  .object({ groups: z.array(ShareDestinationGroup) })
  .meta({ id: 'ListShareDestinationsResponse' });
export type ListShareDestinationsResponse = z.infer<typeof ListShareDestinationsResponse>;

// ─── Shape 9: NeedsReviewResponse ─────────────────────────────────────────────

/** `?review=true` branch — flat, severity-ordered, no `groups`. */
export const NeedsReviewResponse = z
  .object({ items: z.array(ReviewDestination) })
  .meta({ id: 'NeedsReviewResponse' });
export type NeedsReviewResponse = z.infer<typeof NeedsReviewResponse>;

// ─── Shape 10: SharesStats ────────────────────────────────────────────────────

export const SharesStats = z
  .object({
    destinations: z.number().int().nonnegative(),
    endpoints: z.number().int().nonnegative(),
    callSites: z.number().int().nonnegative(),
    needsReview: z.number().int().nonnegative(),
    insecure: z.number().int().nonnegative(),
    byKind: z.object({
      provider: z.number().int().nonnegative(),
      internal: z.number().int().nonnegative(),
      ip: z.number().int().nonnegative(),
    }),
    byTrust: z.object({
      recognized: z.number().int().nonnegative(),
      internal: z.number().int().nonnegative(),
      unverified: z.number().int().nonnegative(),
      ip: z.number().int().nonnegative(),
    }),
  })
  .meta({ id: 'SharesStats' });
export type SharesStats = z.infer<typeof SharesStats>;

// ─── Shape 11: SetEgressDecisionBody ─────────────────────────────────────────

export const SetEgressDecisionBody = z
  .object({
    /** `null` clears the override — reverts to the trust default, isCustom false. */
    decision: EgressDecision.nullable(),
  })
  .meta({ id: 'SetEgressDecisionBody' });
export type SetEgressDecisionBody = z.infer<typeof SetEgressDecisionBody>;

// ─── Shape 12: SetEgressDecisionResponse ─────────────────────────────────────

export const SetEgressDecisionResponse = z
  .object({ destination: ShareDestinationSummary })
  .meta({ id: 'SetEgressDecisionResponse' });
export type SetEgressDecisionResponse = z.infer<typeof SetEgressDecisionResponse>;

// ─── Query schemas ────────────────────────────────────────────────────────────
// Query schemas intentionally carry NO `.meta({ id })`: the OpenAPI generator
// expands query params into individual `parameters` (which cannot be a `$ref`),
// so they must stay inline. See inventory.ts / api.ts header for the same rule.

/** GET /v1/shares/destinations query params. */
export const ListShareDestinationsQuery = z.object({
  /** Case-insensitive match over destination name/category, endpoint url, call-site project/file. */
  q: z.string().optional(),
  /** Repeatable. Restrict to these DestinationKind values; absent means all kinds. */
  kind: z.array(DestinationKind).optional(),
  /** Reserved for future grouping modes; only 'destination' is supported today. */
  groupBy: z.enum(['destination']).default('destination'),
  /** When true, return a flat severity-ordered `items[]` instead of `groups`. */
  review: z.coerce.boolean().default(false),
});
export type ListShareDestinationsQuery = z.infer<typeof ListShareDestinationsQuery>;

/** GET /v1/shares/export query params. */
export const ExportSharesQuery = z.object({
  format: z.enum(['csv', 'json']).default('csv'),
  q: z.string().optional(),
  kind: z.array(DestinationKind).optional(),
});
export type ExportSharesQuery = z.infer<typeof ExportSharesQuery>;
