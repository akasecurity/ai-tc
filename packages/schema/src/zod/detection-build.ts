// Pure detection read-model builders. No I/O, no side effects.
// Shared by every detections read path (e.g. the SQLite adapter in
// @akasecurity/persistence; callers may layer registry update-checks on top), so the
// list/detail shapes can never drift between callers.
//
// Callers supply already-read rows (summaries / a row with parsed rules) and the
// findings-30d count they computed against their own store; these builders only
// shape them into the @akasecurity/schema contract types.
import type {
  DetectionDetail,
  DetectionListItem,
  DetectionUpdate,
  ListDetectionsQuery,
  ListDetectionsResponse,
  OriginEnum,
} from './detection.ts';
import { AppliesTo, Matcher, PostValidatorRef, RequiresNearby, type Rule } from './rule.ts';

/**
 * Spread-able single entry for an optional DetectionRule field: `{ key: value }`
 * when the stored value both exists and validates, `{}` otherwise.
 *
 * Returning the empty object rather than `{ key: undefined }` matters — the
 * DetectionDetail this builds is serialized to JSON on the enterprise HTTP path,
 * and an explicit `undefined` and an absent key are the same thing there but NOT
 * the same thing to a strict deep-equality assertion or to `in`. Absent is what
 * "the rule does not set this" has always looked like, so absent is what it keeps
 * looking like.
 */
function optional<K extends string, T>(
  key: K,
  parsed: { success: boolean; data?: T },
  raw: unknown,
): Partial<Record<K, T>> {
  if (raw === undefined || !parsed.success || parsed.data === undefined) return {};
  return { [key]: parsed.data } as Record<K, T>;
}

/**
 * `examples` is a plain `string[]`, checked with a type guard rather than a Zod
 * schema. This module is reached from the plugin bundle, and a Zod array built at
 * module scope is an un-annotated top-level call a bundler cannot tree-shake,
 * while one built inside this function would be reconstructed per rule. A guard
 * costs neither and says exactly as much about a list of strings.
 */
function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

// ─── Inputs ──────────────────────────────────────────────────────────────────

// The minimal per-pack summary the list/stats views need. Deliberately a
// structural subset of the installed_packs row, so a caller passes its own
// row shape unchanged.
export interface DetectionSummaryInput {
  namespace: string;
  packId: string;
  version: string;
  name: string;
  enabled: boolean;
  ruleCount: number;
  // Where the pack came from. Optional so a caller that predates custom
  // authoring — or a store with no origin column — keeps its current meaning
  // rather than having to be updated in lockstep; absent reads as 'library',
  // which is what every such row is.
  origin?: OriginEnum | null;
  // null/undefined == no policy assigned.
  policyId?: string | null;
  // Set ONLY when a newer snapshot is available for this pack (computed from
  // available_packs vs the installed row). null/undefined == up to date or
  // unknown; a caller that resolves updates lazily on detail omits it, leaving
  // its counts.updates at 0.
  latestVersion?: string | null;
}

// A single installed pack with its parsed rules — what the detail view needs.
export interface DetectionRowInput {
  namespace: string;
  packId: string;
  version: string;
  name: string;
  enabled: boolean;
  rules: Rule[];
  // See DetectionSummaryInput.origin — absent reads as 'library'.
  origin?: OriginEnum | null;
  // The DB-persisted last-edit time (installed_packs.updated_at).
  updatedAt: Date;
  // null/undefined == no policy assigned.
  policyId?: string | null;
}

// ─── Mappers ───────────────────────────────────────────────────────────────

/** Summary row → list item. `id` is the un-encoded "namespace/packId" slug. */
export function summaryToDetectionListItem(s: DetectionSummaryInput): DetectionListItem {
  return {
    id: `${s.namespace}/${s.packId}`,
    name: s.name,
    version: s.version,
    enabled: s.enabled,
    origin: s.origin ?? 'library',
    namespace: s.namespace,
    packId: s.packId,
    ruleCount: s.ruleCount,
    ...(s.policyId != null ? { policyId: s.policyId } : {}),
    ...(s.latestVersion != null ? { latestVersion: s.latestVersion } : {}),
  };
}

/**
 * Installed-pack row → full detail. `findingsLast30d` and `update` are computed
 * by the caller (the store for the count; the registry for the update, or null
 * when there is no registry — the OSS case).
 *
 * Every rule with a valid matcher (regex, keyword, or validator) is exposed — the
 * rule inspector renders all three — so for a well-formed pack `rules.length`
 * equals `ruleCount`. A foreign/partial row whose matcher is missing or fails
 * validation is skipped, so `ruleCount` (full pack count) can still exceed
 * `rules.length` in that defensive case.
 */
export function rowToDetectionDetail(
  row: DetectionRowInput,
  findingsLast30d: number,
  update: DetectionUpdate,
): DetectionDetail {
  const rules = row.rules.flatMap((r) => {
    // `row.rules` may be an un-validated cast (the OSS store parses rules_json
    // tolerantly), so a foreign/partial/tampered row can carry a matcher with
    // the right `type` but a missing field (e.g. `{ type: 'keyword' }` with no
    // `keywords`). Validate the WHOLE matcher against the union rather than
    // trusting the type tag — the inspector dereferences type-specific fields
    // (matcher.keywords.map, …), so a partially-shaped matcher would crash the
    // render. A rule that fails validation is dropped from the detail.
    const parsed = Matcher.safeParse(r.matcher);
    if (!parsed.success) return [];
    return [
      {
        id: r.id,
        name: r.name,
        category: r.category,
        severity: r.severity,
        matcher: parsed.data,
        // The rest of what decides whether this rule fires. Carried so a consumer
        // re-running the rule (a preview, a tester) evaluates what the engine
        // evaluates rather than a matcher stripped of its guards — half the
        // bundled catalog carries at least one of these.
        //
        // Enrichment is deliberately per-field and best-effort, NOT a whole-rule
        // `Rule.safeParse`. Two reasons: `Rule` is a strict object pinned to
        // `specVersion: 1`, so validating the whole thing would DROP any stored
        // rule missing or predating that literal — turning a display-fidelity
        // improvement into rules vanishing from the inspector; and the inclusion
        // test should stay exactly what it was, namely a renderable matcher. A
        // field that fails validation is omitted, which reads as "not set" and is
        // the same thing the consumer saw before this change.
        ...optional('appliesTo', AppliesTo.safeParse(r.appliesTo), r.appliesTo),
        ...optional(
          'postValidators',
          PostValidatorRef.array().safeParse(r.postValidators),
          r.postValidators,
        ),
        ...optional('requiresNearby', RequiresNearby.safeParse(r.requiresNearby), r.requiresNearby),
        ...optional(
          'examples',
          { success: isStringArray(r.examples), data: r.examples },
          r.examples,
        ),
      },
    ];
  });

  return {
    id: `${row.namespace}/${row.packId}`,
    name: row.name,
    version: row.version,
    enabled: row.enabled,
    origin: row.origin ?? 'library',
    namespace: row.namespace,
    packId: row.packId,
    ruleCount: row.rules.length,
    editedAt: row.updatedAt.toISOString(),
    findingsLast30d,
    latestVersion: update ? update.latestVersion : null,
    update,
    rules,
    modified: false,
    ...(row.policyId != null ? { policyId: row.policyId } : {}),
  };
}

/**
 * Decode a detection id slug ("namespace/packId") back into its parts — the exact
 * inverse of the `${namespace}/${packId}` encoding used by the mappers above.
 * Returns null for a malformed slug (no interior '/', or an empty namespace/
 * packId). Splits on the FIRST '/' so a packId may itself contain slashes. This is
 * the single decoder shared by every OSS caller (the persistence detail read and
 * the web-ui write actions) so the id contract has one encoder and one decoder.
 */
export function splitDetectionId(id: string): { namespace: string; packId: string } | null {
  const idx = id.indexOf('/');
  if (idx < 1 || idx === id.length - 1) return null;
  return { namespace: id.slice(0, idx), packId: id.slice(idx + 1) };
}

// ─── List builder (counts + filter + sort) ───────────────────────────────────

/**
 * Build the GET /v1/detections response from the unfiltered summary set. Counts
 * are computed over the UNFILTERED set; `custom`/`customized` are 0 in v1 (no
 * branching model). `updates` counts summaries carrying `latestVersion` —
 * populated from available_packs; a caller that resolves updates lazily on
 * detail omits it, keeping its count 0.
 * Filtering is case-insensitive over name/packId/namespace; sort is enabled
 * DESC then name ASC.
 */
export function buildDetectionsList(
  summaries: DetectionSummaryInput[],
  query: ListDetectionsQuery,
): ListDetectionsResponse {
  const withUpdate = summaries.filter((s) => s.latestVersion != null);
  const isCustom = (s: DetectionSummaryInput) => (s.origin ?? 'library') === 'custom';
  const counts = {
    all: summaries.length,
    library: summaries.filter((s) => !isCustom(s)).length,
    custom: summaries.filter(isCustom).length,
    // No origin member produces this, so it is 0 BY CONSTRUCTION rather than by
    // omission: `customized` would mean a LIBRARY pack whose rules were edited in
    // place, and that state does not exist — editing a library pack forks it. See
    // OriginEnum.
    customized: 0,
    updates: withUpdate.length,
  };

  // `filter` defaults to 'all' via the Zod schema, so it is always present here.
  const filter = query.filter;
  // 'customized' has no producer (see counts above), so it stays the one arm
  // that is empty by construction; 'updates' narrows to the packs carrying a
  // newer snapshot, and the two origin arms partition everything else.
  let filtered =
    filter === 'customized'
      ? []
      : filter === 'custom'
        ? summaries.filter(isCustom)
        : filter === 'library'
          ? summaries.filter((s) => !isCustom(s))
          : filter === 'updates'
            ? [...withUpdate]
            : [...summaries];

  if (query.q) {
    const q = query.q.toLowerCase();
    filtered = filtered.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.packId.toLowerCase().includes(q) ||
        s.namespace.toLowerCase().includes(q),
    );
  }

  filtered.sort((a, b) => {
    if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  return { counts, items: filtered.map(summaryToDetectionListItem) };
}
