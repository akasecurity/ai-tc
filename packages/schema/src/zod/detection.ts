// Detections API contracts — v1 (control-plane only, no registry fan-out in this file)
// All shapes defined here are contracts-first; service and route code consume them.
import { z } from 'zod';

import { DetectionCategory, Severity } from './finding.ts';
import { Namespace, PackId, PublisherKind, SemVer } from './registry.ts';
// Matcher (the keyword|regex|validator union) + RegexMatcher already defined in
// rule.ts — import rather than redefine to avoid collision. AppliesTo /
// PostValidatorRef / RequiresNearby come from there for the same reason: they are
// the rule's own field shapes, and DetectionRule reports them verbatim.
import { AppliesTo, Matcher, PostValidatorRef, RegexMatcher, RequiresNearby } from './rule.ts';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

// Where an installed pack came from.
//
//   library — installed from the rule registry. Its rules are an immutable
//             snapshot of a published version, so they are never edited in place;
//             moving forward means pulling a new version.
//   custom  — authored by the user. There is no upstream, so nothing to track,
//             diff, or update against, and its rules ARE editable.
//
// `DetectionFilterEnum` also carries `customized`, which has no origin member and
// deliberately none yet: it would mean a LIBRARY pack whose rules were edited in
// place, and that state does not exist — editing a library pack is forking it.
// Adding the member before anything can produce it is what left `custom` itself
// unreachable for as long as it was.
export const OriginEnum = z.enum(['library', 'custom']).meta({ id: 'OriginEnum' });
export type OriginEnum = z.infer<typeof OriginEnum>;

// Filter options for the detections read.
// NOT `.meta({ id })`: this enum is only used in querystring position, and a
// consumer expands those properties into individual parameters, which cannot be
// a reference to a named shape. See the SHAPE IDS note in zod/index.ts.
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

// Counts object returned by the detections read. Computed over the UNFILTERED set.
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

// A single item in the detections read's response.
// `id` is the un-encoded "namespace/packId" slug (clients encode it for detail/update).
// `update` is always null on list (lazy-computed on detail only to avoid N registry calls).
// `origin` is 'library' for a pack installed from the registry and 'custom' for
// one authored here — see OriginEnum. Same field, same meaning, on DetectionDetail.
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

// Response shape for the detections read.
export const ListDetectionsResponse = z
  .object({
    counts: DetectionCounts,
    items: z.array(DetectionListItem),
  })
  .meta({ id: 'ListDetectionsResponse' });
export type ListDetectionsResponse = z.infer<typeof ListDetectionsResponse>;

// Query params for the detections read.
// NOT `.meta({ id })`: querystring schemas stay inline, like every other query
// shape here. See the SHAPE IDS note in zod/index.ts.
export const ListDetectionsQuery = z.object({
  filter: DetectionFilterEnum.optional().default('all'),
  q: z.string().optional(),
});
export type ListDetectionsQuery = z.infer<typeof ListDetectionsQuery>;

// Response shape for the detection-stats read.
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
//
// The four optional fields below are the rest of what actually decides whether a
// rule fires. They are already stored — `rules_json` holds parsed `Rule` objects
// in both the local SQLite store and the tenant Postgres one — and were simply
// projected away here, which made this shape a description of a rule the engine
// does not run. Half the bundled catalog is affected: of 101 rules, 21 carry
// `postValidators`, 19 `appliesTo`, 17 `requiresNearby` (50 distinct rules), and
// all 101 carry `examples`.
//
// That gap is not cosmetic for anything that re-runs a rule from this shape. A
// rule whose `postValidators` are dropped loses its false-positive guard and
// appears to match strings it would never report; one whose `appliesTo` is
// dropped appears to fire in files it is scoped out of. A preview built on the
// projected shape would therefore have been confidently wrong about half the
// catalog — the same class of defect as a fixture that passes for the wrong
// reason.
//
// Optional rather than required so a stored rule that predates a field, or whose
// value fails validation, still yields a DetectionRule (see rowToDetectionDetail:
// each field is validated independently and omitted on failure, and only an
// invalid `matcher` drops the rule itself).
export const DetectionRule = z
  .object({
    id: z.string(),
    name: z.string(),
    category: DetectionCategory,
    severity: Severity,
    matcher: Matcher,
    // File-extension scoping. Absent means the rule runs everywhere.
    appliesTo: AppliesTo.optional(),
    // False-positive guards (entropy, luhn) applied to each candidate match.
    postValidators: z.array(PostValidatorRef).optional(),
    // Co-occurrence / proximity gate a candidate must clear to be kept.
    requiresNearby: RequiresNearby.optional(),
    // Representative matching strings the rule author shipped with the rule. The
    // cheapest honest answer to "show me what this rule catches" — every bundled
    // rule has them, and they are already in the stored snapshot.
    examples: z.array(z.string()).optional(),
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

// Full detail for a single detection.
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

// A library item in the detection-library read.
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

// Response shape for the detection-library read.
export const ListLibraryResponse = z
  .object({
    categories: z.array(DetectionCategory),
    items: z.array(LibraryItem),
  })
  .meta({ id: 'ListLibraryResponse' });
export type ListLibraryResponse = z.infer<typeof ListLibraryResponse>;

// Request body for a detection import.
// `libraryId` must be in `namespace/packId` format.
export const ImportDetectionRequest = z
  .object({
    libraryId: z.string().refine((v) => /^[^/]+\/[^/]+$/.test(v), {
      message: 'libraryId must be in namespace/packId format',
    }),
  })
  .meta({ id: 'ImportDetectionRequest' });
export type ImportDetectionRequest = z.infer<typeof ImportDetectionRequest>;
