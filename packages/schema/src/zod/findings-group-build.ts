// Pure, tenant-free findings grouping + enum translation. No I/O, no side
// effects. Shared by every findings read path (e.g. the SQLite adapter in
// @akasecurity/persistence; callers layer overrides/pack-names/cursor
// pagination on top), so the grouped-findings shape can never drift between
// callers.
//
// The grouping algorithm and the DB↔API enum mappings are NORMATIVE (derived
// from the findings spec enum tables). Keep this a behavior-preserving home for
// that logic — callers add their own concerns (overrides, pack names, cursors)
// around these primitives.
import type {
  FindingAction,
  FindingCategory,
  FindingFacetItem,
  FindingFacets,
  FindingGroup,
  FindingInstance,
  FindingProvider,
  FindingStatus,
  Severity,
} from './finding.ts';
import { TOOL_TO_HARNESS } from './harness-map.ts';

// ─── Enum translation (DB storage values ↔ API-facing enums) ─────────────────

/**
 * DB ActionTaken → API FindingAction.
 *   log → monitored · block → blocked · redact → redacted · warn → warned · allow → allowed
 * Unknown values fall back to 'allowed' (safe, non-destructive).
 */
export function toApiAction(dbVal: string): FindingAction {
  const map: Record<string, FindingAction> = {
    log: 'monitored',
    block: 'blocked',
    redact: 'redacted',
    warn: 'warned',
    allow: 'allowed',
  };
  return map[dbVal] ?? 'allowed';
}

/**
 * API FindingAction → DB ActionTaken string. Reverse of toApiAction.
 * 'quarantined' is system-assigned — throws so the service layer catches it
 * before persisting. 'monitored' → 'log'.
 */
export function toDbAction(apiVal: FindingAction): string {
  if (apiVal === 'quarantined') {
    throw new Error('quarantined is system-assigned and cannot be stored as a DB action');
  }
  const map: Record<FindingAction, string> = {
    monitored: 'log',
    blocked: 'block',
    redacted: 'redact',
    warned: 'warn',
    allowed: 'allow',
    // quarantined handled above
    quarantined: 'quarantined', // unreachable — only for type completeness
  };
  return map[apiVal];
}

/**
 * DB DetectionCategory → API FindingCategory.
 *   code_context → source_code.
 * NOT a clean 1:1: FindingCategory does NOT include every DetectionCategory —
 * `code_flaw` and `config` have no FindingCategory member, so for those the cast
 * below passes an OFF-ENUM string through (a known gap — they don't reach the
 * legacy findings API today; config findings live in inspection_findings and
 * code_flaw findings are not yet surfaced on the findings read model). Every other
 * category is a genuine 1:1 pass-through.
 */
export function toApiCategory(dbVal: string): FindingCategory {
  if (dbVal === 'code_context') return 'source_code';
  return dbVal as FindingCategory;
}

/**
 * API FindingCategory → DB DetectionCategory string.
 *   source_code → code_context · all others are 1:1 pass-through
 */
export function toDbCategory(apiVal: FindingCategory): string {
  if (apiVal === 'source_code') return 'code_context';
  return apiVal;
}

/**
 * event.sourceTool → API FindingProvider (claude-desktop and claudecode are
 * distinct values and must never be merged).
 *   claude-code → claudecode · claude-desktop → claudedesktop ·
 *   github-copilot → copilot · cursor → cursor · chatgpt → chatgpt · else → api
 */
export function toApiProvider(sourceTool: string): FindingProvider {
  // Shares the single TOOL_TO_HARNESS table (harness-map.ts) with
  // `harnessFromTool`; every mapped value is a valid FindingProvider, and an
  // unknown tool falls back to 'api' (whereas harnessFromTool passes it through).
  return (TOOL_TO_HARNESS[sourceTool] as FindingProvider | undefined) ?? 'api';
}

/**
 * API FindingProvider → DB sourceTool filter values (string[]).
 * claudecode and claudedesktop must never be merged. 'api' → [] (matches any
 * unknown value; the filter is applied in-memory).
 */
export function toDbProviderFilter(apiProvider: FindingProvider): string[] {
  const map: Record<FindingProvider, string[]> = {
    claudecode: ['claude-code'],
    claudedesktop: ['claude-desktop'],
    copilot: ['github-copilot'],
    cursor: ['cursor'],
    chatgpt: ['chatgpt'],
    api: [], // 'api' catches unknown tools — applied in-memory (no single DB value)
  };
  return map[apiProvider];
}

// ─── Grouping ────────────────────────────────────────────────────────────────

/**
 * A tenant-free finding row (a finding joined with its parent event), the input
 * to buildFindingGroups. Callers project their storage rows onto this shape:
 * the SQLite adapter maps the
 * findings⋈events join. `occurredAt` is ISO; `repo`/`file` come from the event
 * metadata (empty string when absent). Severity/category/actionTaken carry the
 * raw DB values — the mappers above translate them here.
 */
export interface GroupableFindingRow {
  id: string;
  ruleId: string;
  category: string;
  severity: string;
  maskedMatch: string;
  actionTaken: string;
  confidence: number;
  occurredAt: string;
  sourceTool: string;
  repo: string;
  file: string;
  // Lifecycle status (see FindingStatus in finding.ts). Stored 1:1 with the
  // FindingStatus values (no DB↔API translation, unlike actionTaken/category —
  // see resolutions.ts). Optional/absent for legacy rows that predate the
  // resolution feature.
  status?: FindingStatus;
}

// Group-level status precedence: open dominates, then handled, then dismissed,
// then resolved. A group is only 'open' if at least one instance is open; it
// is 'resolved' only when every status-carrying instance is resolved (the
// least urgent outcome). Lower index = higher precedence.
//
// DECISION: handled outranks dismissed — NOT the reverse.
// A group can legitimately mix an actively-enforced (handled) in-flight
// instance with an at-rest instance a human dismissed as accepted risk; if
// dismissed took precedence, the group would read "Dismissed" (a neutral
// "done" badge) and disappear from a "handled" status filter even though it
// still contains a live enforcement action worth surfacing. Enforcement in
// progress is more informative than a human's risk acceptance, so it wins.
const STATUS_PRECEDENCE: readonly FindingStatus[] = ['open', 'handled', 'dismissed', 'resolved'];

/**
 * Fold a group's instance statuses into a single group-level status using
 * open-dominates precedence (see STATUS_PRECEDENCE). Instances lacking a
 * status are ignored; if NO instance carries a status, returns undefined
 * (never fabricates a status for legacy rows).
 */
function deriveGroupStatus(instances: FindingInstance[]): FindingStatus | undefined {
  const statuses = new Set(
    instances.map((i) => i.status).filter((s): s is FindingStatus => s !== undefined),
  );
  if (statuses.size === 0) return undefined;
  for (const candidate of STATUS_PRECEDENCE) {
    if (statuses.has(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Per-FINDING lifecycle status from the raw classification inputs — the ONE
 * classifier every store uses (e.g. SqliteFindingsRepository), so no two read
 * paths can disagree
 * on what a row's Status column reads:
 *   - in-flight (kind != 'code_change') is born 'handled' — enforcement
 *     already ran at the boundary.
 *   - at-rest, legacy untracked (findingKey null): the resolution lifecycle is
 *     keyed by finding_key, so these can never carry a disposition. The
 *     severity summaries drop them from their caught/open buckets entirely; a
 *     list view still needs a status to render, and the finding physically
 *     exists and is unremediated, so it reads 'open' rather than being
 *     fabricated as resolved/handled.
 *   - at-rest, tracked: 'resolved'/'dismissed' per the LATEST
 *     finding_resolution row (latest-resolution-wins — the caller's SQL
 *     supplies it), else 'open'.
 * DECISION: 'dismissed' deliberately reads as its own label
 * here while the severity summaries keep counting it under needs-remediation
 * ('caught' honors only 'resolved') — dismissing is a judgment, not a
 * remediation, and the card must never understate exposure. Values come from
 * a fixed literal set, so the result is in-enum without a cast.
 */
export function deriveFindingStatus(row: {
  kind: string;
  findingKey: string | null;
  latestResolutionStatus: string | null;
}): FindingStatus {
  const atRest = row.kind === 'code_change';
  if (!atRest) return 'handled';
  if (row.findingKey === null) return 'open';
  if (row.latestResolutionStatus === 'resolved') return 'resolved';
  if (row.latestResolutionStatus === 'dismissed') return 'dismissed';
  return 'open';
}

export interface BuildGroupsOptions {
  /** findingId → DB action override. Absent ⇒ no overrides. */
  overrides?: Map<string, string>;
  /** ruleId → pack display name. Absent ⇒ detection.name is null. */
  packNames?: Map<string, string>;
}

/**
 * Group GroupableFindingRow[] by ruleId into FindingGroup[]. Rows are expected
 * newest-first (that order is preserved into each group's instances). An
 * override in `opts.overrides` takes precedence over the row's actionTaken.
 */
export function buildFindingGroups(
  rows: GroupableFindingRow[],
  opts: BuildGroupsOptions = {},
): FindingGroup[] {
  const overrides = opts.overrides;
  const packNames = opts.packNames;

  // Collect rows per ruleId, preserving order (rows arrive newest-first).
  const byRuleId = new Map<string, GroupableFindingRow[]>();
  for (const row of rows) {
    const existing = byRuleId.get(row.ruleId);
    if (existing) existing.push(row);
    else byRuleId.set(row.ruleId, [row]);
  }

  const groups: FindingGroup[] = [];

  for (const [ruleId, ruleRows] of byRuleId) {
    const instances: FindingInstance[] = ruleRows.map((r): FindingInstance => {
      const effectiveDbAction = overrides?.get(r.id) ?? r.actionTaken;
      return {
        id: r.id,
        provider: toApiProvider(r.sourceTool),
        repo: r.repo,
        file: r.file,
        action: toApiAction(effectiveDbAction),
        detectedAt: r.occurredAt,
        confidence: r.confidence,
        status: r.status,
      };
    });

    // latestDetectedAt: ISO strings sort lexically, so string max works.
    const latestDetectedAt = ruleRows.reduce<string>(
      (max, r) => (r.occurredAt > max ? r.occurredAt : max),
      ruleRows[0]?.occurredAt ?? new Date(0).toISOString(),
    );

    // providers: dedup preserving order of first occurrence.
    const seenProviders = new Set<string>();
    const providers = instances
      .map((i) => i.provider)
      .filter((p) => {
        if (seenProviders.has(p)) return false;
        seenProviders.add(p);
        return true;
      });

    // aggregateAction: uniform → value; mixed → null.
    const actionSet = new Set(instances.map((i) => i.action));
    const aggregateAction = actionSet.size === 1 ? ([...actionSet][0] ?? null) : null;

    const severity = (ruleRows[0]?.severity ?? 'low') as Severity;

    const detection = {
      id: ruleId,
      name: packNames?.get(ruleId) ?? null,
    };

    // policy: synthesized by category — id = `category:{apiCategory}`, name =
    // apiCategory display string (findings have no FK to a specific policy yet).
    const apiCategory = toApiCategory(ruleRows[0]?.category ?? 'custom');
    const policy = { id: `category:${apiCategory}`, name: apiCategory };

    const match = {
      maskedValue: ruleRows[0]?.maskedMatch ?? '',
      contextPrefix: '', // empty (pending privacy review)
    };

    const status = deriveGroupStatus(instances);

    groups.push({
      id: ruleId,
      category: apiCategory,
      subtype: ruleId, // human label comes with pack metadata later
      severity,
      match,
      detection,
      policy,
      instanceCount: instances.length,
      providers,
      aggregateAction,
      latestDetectedAt,
      instances,
      status,
    });
  }

  return groups;
}

// ─── Filtering ───────────────────────────────────────────────────────────────

export interface FindingFilterOptions {
  // `| undefined` (not just optional) so callers may pass a field through
  // explicitly as undefined under exactOptionalPropertyTypes.
  severity?: string[] | undefined;
  providers?: string[] | undefined;
  actions?: string[] | undefined;
  q?: string | undefined;
  subtype?: string[] | undefined;
}

// The lowercased free-text haystack for a group is immutable once the group is
// built, but applyFindingFilters runs up to 5× per request (once per facet
// dimension + the final filtered set). Memoise it per group object so the
// join/lowercase happens once instead of once per pass. Keyed weakly so groups
// are collected with the request that produced them (no cross-request leak).
const haystackCache = new WeakMap<FindingGroup, string>();

function groupHaystack(g: FindingGroup): string {
  const cached = haystackCache.get(g);
  if (cached !== undefined) return cached;
  // subtype, category, maskedMatch, policy name, id, and each instance's repo/file/id.
  const haystack = [
    g.subtype,
    g.category,
    g.match.maskedValue,
    g.policy.name,
    g.id,
    ...g.instances.map((i) => i.repo),
    ...g.instances.map((i) => i.file),
    ...g.instances.map((i) => i.id),
  ]
    .join(' ')
    .toLowerCase();
  haystackCache.set(g, haystack);
  return haystack;
}

export function applyFindingFilters(
  groups: FindingGroup[],
  opts: FindingFilterOptions,
): FindingGroup[] {
  let filtered = groups;

  if (opts.severity && opts.severity.length > 0) {
    const sevSet = new Set(opts.severity);
    filtered = filtered.filter((g) => sevSet.has(g.severity));
  }

  // Provider: keep groups with at least one instance on a matching provider.
  if (opts.providers && opts.providers.length > 0) {
    const providerSet = new Set(opts.providers);
    filtered = filtered.filter((g) => g.providers.some((p) => providerSet.has(p)));
  }

  // Action: keep groups where at least one instance has a matching action.
  if (opts.actions && opts.actions.length > 0) {
    const actionSet = new Set(opts.actions);
    filtered = filtered.filter((g) => g.instances.some((i) => actionSet.has(i.action)));
  }

  if (opts.subtype && opts.subtype.length > 0) {
    const subtypeSet = new Set(opts.subtype);
    filtered = filtered.filter((g) => subtypeSet.has(g.subtype));
  }

  // q: case-insensitive substring over the group's cached search haystack
  // (subtype, category, maskedMatch, policy name, id, and each instance's
  // repo/file/id) — see groupHaystack.
  if (opts.q) {
    const q = opts.q.toLowerCase();
    filtered = filtered.filter((g) => groupHaystack(g).includes(q));
  }

  return filtered;
}

// ─── Sorting ─────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
// Partial map so lookups on unexpected DB values return undefined (→ fallback
// -1) rather than a type-error-suppressed gap; keeps sort deterministic.
const SEVERITY_RANK = SEVERITY_ORDER as Partial<Record<string, number>>;

export function sortFindingGroups(groups: FindingGroup[]): FindingGroup[] {
  return [...groups].sort((a, b) => {
    const rankA = SEVERITY_RANK[a.severity] ?? -1;
    const rankB = SEVERITY_RANK[b.severity] ?? -1;
    const severityDiff = rankA - rankB;
    if (severityDiff !== 0) return severityDiff;
    // latestDetectedAt desc — ISO strings sort lexically.
    return b.latestDetectedAt.localeCompare(a.latestDetectedAt);
  });
}

// ─── Facets (per-filter-excluded counts) ─────────────────────────────────────

/**
 * Per-dimension facet counts, each computed by applying all filters EXCEPT that
 * dimension's own — so "how many groups if I also pick X?" stays answerable.
 */
export function computeFindingFacets(
  allGroups: FindingGroup[],
  opts: FindingFilterOptions,
): FindingFacets {
  const forSeverity = applyFindingFilters(allGroups, {
    providers: opts.providers,
    actions: opts.actions,
    q: opts.q,
    subtype: opts.subtype,
  });
  const severityMap = new Map<string, number>();
  for (const g of forSeverity) {
    severityMap.set(g.severity, (severityMap.get(g.severity) ?? 0) + 1);
  }

  const forProvider = applyFindingFilters(allGroups, {
    actions: opts.actions,
    q: opts.q,
    subtype: opts.subtype,
    severity: opts.severity,
  });
  const providerMap = new Map<string, number>();
  for (const g of forProvider) {
    for (const p of g.providers) providerMap.set(p, (providerMap.get(p) ?? 0) + 1);
  }

  const forAction = applyFindingFilters(allGroups, {
    providers: opts.providers,
    q: opts.q,
    subtype: opts.subtype,
    severity: opts.severity,
  });
  const actionMap = new Map<string, number>();
  for (const g of forAction) {
    const actionSet = new Set(g.instances.map((i) => i.action));
    for (const a of actionSet) actionMap.set(a, (actionMap.get(a) ?? 0) + 1);
  }

  const forSubtype = applyFindingFilters(allGroups, {
    providers: opts.providers,
    actions: opts.actions,
    q: opts.q,
    severity: opts.severity,
  });
  const subtypeMap = new Map<string, number>();
  for (const g of forSubtype) subtypeMap.set(g.subtype, (subtypeMap.get(g.subtype) ?? 0) + 1);

  const toItems = (m: Map<string, number>): FindingFacetItem[] =>
    [...m.entries()].map(([value, count]) => ({ value, count }));

  return {
    severity: toItems(severityMap),
    provider: toItems(providerMap),
    action: toItems(actionMap),
    subtype: toItems(subtypeMap),
  };
}
