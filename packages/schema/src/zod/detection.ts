// Detections API contracts — v1 (control-plane only, no registry fan-out in this file)
// All shapes defined here are contracts-first; service and route code consume them.
import { z } from 'zod';

import { DetectionCategory, Severity } from './finding.ts';
import { Namespace, PackId, PublisherKind, SemVer } from './registry.ts';
// Matcher (the keyword|regex|validator union) + RegexMatcher already defined in
// rule.ts — import rather than redefine to avoid collision.
import { Matcher, RegexMatcher } from './rule.ts';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

// In v1 the only origin is "library" (no custom-authoring model yet).
export const OriginEnum = z.enum(['library']).meta({ id: 'OriginEnum' });
export type OriginEnum = z.infer<typeof OriginEnum>;

// Filter options for GET /v1/detections.
// NOT `.meta({ id })`: this enum is only used in querystring position, and a
// named-component `$ref` inside route parameters crashes @fastify/swagger's
// param resolver. Query-param schemas stay inline (see ListEventsQuery/ListFindingsQuery).
export const DetectionFilterEnum = z.enum(['all', 'library', 'custom', 'customized', 'updates']);
export type DetectionFilterEnum = z.infer<typeof DetectionFilterEnum>;

// State of a library item relative to the installed packs.
export const LibraryStateEnum = z
  .enum(['new', 'imported', 'update'])
  .meta({ id: 'LibraryStateEnum' });
export type LibraryStateEnum = z.infer<typeof LibraryStateEnum>;

// ---------------------------------------------------------------------------
// List & stats shapes
// ---------------------------------------------------------------------------

// Counts object returned in GET /v1/detections. Computed over the UNFILTERED set.
export const DetectionCounts = z
  .object({
    all: z.number().int().nonnegative(),
    library: z.number().int().nonnegative(),
    custom: z.number().int().nonnegative(),
    customized: z.number().int().nonnegative(),
    updates: z.number().int().nonnegative(),
  })
  .meta({ id: 'DetectionCounts' });
export type DetectionCounts = z.infer<typeof DetectionCounts>;

// A single item in the GET /v1/detections response.
// `id` is the un-encoded "namespace/packId" slug (clients encode it for detail/update).
// `update` is always null on list (lazy-computed on detail only to avoid N registry calls).
// `origin` is always "library" in v1.
export const DetectionListItem = z
  .object({
    id: z.string(),
    name: z.string(),
    version: SemVer,
    enabled: z.boolean(),
    origin: OriginEnum,
    publisher: Namespace.optional(),
    publisherKind: PublisherKind.optional(),
    ruleCount: z.number().int().nonnegative(),
    namespace: Namespace,
    packId: PackId,
    // Per-pack enforcement-policy assignment. Holds a BuiltinPolicyId ARCHETYPE
    // (monitor|warn|redact|block) — NOT a policies-table Policy.id guid; a
    // detection is a PACK, and its policy is the archetype applied to all its
    // rules. Absent == unassigned, which resolves to Monitor everywhere
    // (DEFAULT_PACK_POLICY_ID). Every enforcement surface expands it into
    // per-rule policies (see policyIdToAction). Typed z.string() (not
    // the enum) to keep the OpenAPI response tolerant of a future custom id.
    policyId: z.string().optional(),
    // Set ONLY when a newer snapshot is available for this pack (OSS: the
    // bundled inventory recorded in available_packs differs from the installed
    // row). Absent == up to date or unknown. Powers the list's per-row update
    // badge and the `updates` filter/count without a per-item detail read.
    latestVersion: SemVer.optional(),
  })
  .meta({ id: 'DetectionListItem' });
export type DetectionListItem = z.infer<typeof DetectionListItem>;

// Response shape for GET /v1/detections.
export const ListDetectionsResponse = z
  .object({
    counts: DetectionCounts,
    items: z.array(DetectionListItem),
  })
  .meta({ id: 'ListDetectionsResponse' });
export type ListDetectionsResponse = z.infer<typeof ListDetectionsResponse>;

// Query params for GET /v1/detections.
// NOT `.meta({ id })`: querystring schemas must stay inline (a named-component
// `$ref` in parameters crashes @fastify/swagger). Matches ListEventsQuery/ListFindingsQuery.
export const ListDetectionsQuery = z.object({
  filter: DetectionFilterEnum.optional().default('all'),
  q: z.string().optional(),
});
export type ListDetectionsQuery = z.infer<typeof ListDetectionsQuery>;

// Response shape for GET /v1/detections/stats.
export const DetectionStats = z
  .object({
    detections: z.number().int().nonnegative(),
    rules: z.number().int().nonnegative(),
    active: z.number().int().nonnegative(),
    findingsLast30d: z.number().int().nonnegative(),
  })
  .meta({ id: 'DetectionStats' });
export type DetectionStats = z.infer<typeof DetectionStats>;

// ---------------------------------------------------------------------------
// Detail & update shapes
// ---------------------------------------------------------------------------

// Re-export the matcher shapes from rule.ts so detection consumers can import
// them from here (Matcher is the full keyword|regex|validator union).
export { Matcher, RegexMatcher };

// A single rule in a DetectionDetail. `matcher` is the full Matcher union — the
// rule inspector renders regex, keyword, and validator matchers alike, so a pack
// with keyword/validator rules exposes all of them (not just its regex rules).
export const DetectionRule = z
  .object({
    id: z.string(),
    name: z.string(),
    category: DetectionCategory,
    severity: Severity,
    matcher: Matcher,
  })
  .meta({ id: 'DetectionRule' });
export type DetectionRule = z.infer<typeof DetectionRule>;

// Update availability info — only computed on detail (lazy, avoids N registry calls).
export const DetectionUpdate = z
  .object({
    available: z.boolean(),
    latestVersion: SemVer,
    // Rule count of the latest snapshot. Lets the update UI show a meaningful
    // delta ("2 rules → 14 rules") when the version did NOT change but the rule
    // content did — the OSS store compares content, not just version. Optional:
    // registry-backed updates omit it.
    latestRuleCount: z.number().int().nonnegative().optional(),
  })
  .nullable()
  .meta({ id: 'DetectionUpdate' });
export type DetectionUpdate = z.infer<typeof DetectionUpdate>;

// Full detail for GET /v1/detections/:id.
export const DetectionDetail = z
  .object({
    id: z.string(),
    name: z.string(),
    version: SemVer,
    enabled: z.boolean(),
    origin: OriginEnum,
    publisher: Namespace.optional(),
    publisherKind: PublisherKind.optional(),
    ruleCount: z.number().int().nonnegative(),
    namespace: Namespace,
    packId: PackId,
    description: z.string().optional(),
    editedAt: z.iso.datetime(),
    findingsLast30d: z.number().int().nonnegative(),
    latestVersion: SemVer.nullable().optional(),
    update: DetectionUpdate,
    rules: z.array(DetectionRule),
    modified: z.boolean(),
    // Per-pack enforcement-policy assignment. Holds a BuiltinPolicyId ARCHETYPE
    // (monitor|warn|redact|block) — NOT a policies-table Policy.id guid; a
    // detection is a PACK, and its policy is the archetype applied to all its
    // rules. Absent == unassigned, which resolves to Monitor everywhere
    // (DEFAULT_PACK_POLICY_ID). Every enforcement surface expands it into
    // per-rule policies (see policyIdToAction). Typed z.string() (not
    // the enum) to keep the OpenAPI response tolerant of a future custom id.
    policyId: z.string().optional(),
  })
  .meta({ id: 'DetectionDetail' });
export type DetectionDetail = z.infer<typeof DetectionDetail>;

// A library item for GET /v1/detections/library.
export const LibraryItem = z
  .object({
    id: z.string(),
    name: z.string(),
    publisher: Namespace,
    publisherKind: PublisherKind.optional(),
    // LOSSY single-category view of a pack. A pack MAY span several categories;
    // this carries only the canonical-first one for display. Do NOT filter/facet
    // on it — the library filter matches a pack's full category set (see
    // ListLibraryResponse.categories).
    category: DetectionCategory.optional(),
    version: SemVer,
    ruleCount: z.number().int().nonnegative(),
    description: z.string().optional(),
    updatedAt: z.iso.datetime(),
    state: LibraryStateEnum,
    importedAs: z.string().nullable(),
  })
  .meta({ id: 'LibraryItem' });
export type LibraryItem = z.infer<typeof LibraryItem>;

// Response shape for GET /v1/detections/library.
export const ListLibraryResponse = z
  .object({
    categories: z.array(DetectionCategory),
    items: z.array(LibraryItem),
  })
  .meta({ id: 'ListLibraryResponse' });
export type ListLibraryResponse = z.infer<typeof ListLibraryResponse>;

// Request body for POST /v1/detections/import.
// `libraryId` must be in `namespace/packId` format.
export const ImportDetectionRequest = z
  .object({
    libraryId: z.string().refine((v) => /^[^/]+\/[^/]+$/.test(v), {
      message: 'libraryId must be in namespace/packId format',
    }),
  })
  .meta({ id: 'ImportDetectionRequest' });
export type ImportDetectionRequest = z.infer<typeof ImportDetectionRequest>;
