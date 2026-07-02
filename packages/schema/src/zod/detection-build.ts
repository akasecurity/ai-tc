// Pure, tenant-free detection read-model builders. No I/O, no side effects.
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
} from './detection.ts';
import { Matcher, type Rule } from './rule.ts';

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
    origin: 'library', // v1: every installed pack is library origin
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
      },
    ];
  });

  return {
    id: `${row.namespace}/${row.packId}`,
    name: row.name,
    version: row.version,
    enabled: row.enabled,
    origin: 'library',
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
  const counts = {
    all: summaries.length,
    library: summaries.length, // all origin=library in v1
    custom: 0,
    customized: 0,
    updates: withUpdate.length,
  };

  // `filter` defaults to 'all' via the Zod schema, so it is always present here.
  const filter = query.filter;
  // 'all' and 'library' include everything in v1; custom/customized have no
  // members yet; 'updates' narrows to the packs with a newer snapshot.
  let filtered =
    filter === 'custom' || filter === 'customized'
      ? []
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
