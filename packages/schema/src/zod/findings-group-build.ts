// Pure finding-TYPE folding + enum translation. No I/O, no side effects.
// Shared by every findings read path (e.g. the SQLite adapter in
// @akasecurity/persistence; callers layer pack-names and cursor pagination on
// top), so the type-level shape can never drift between callers.
//
// The fold and the DB↔API enum mappings are NORMATIVE (derived from the findings
// spec enum tables). Keep this a behavior-preserving home for that logic —
// callers add their own concerns (pack names, cursors) around these primitives.
//
// Nothing here materializes a finding: a type is built from its store-side
// aggregate alone, and the findings OF a type are a separate keyset-paged read
// (ListFindingInstancesQuery, scoped to `subtype`). That split is what removes
// the per-type cap this module used to impose.
import type {
  FindingAction,
  FindingFacetItem,
  FindingFacets,
  FindingProvider,
  FindingStatus,
  FindingTypeSummary,
  FindingUser,
  Severity,
} from './finding.ts';
// Value import: the fallback below validates against the enum itself, so a member
// added to FindingCategory is honored here without restating the member list.
import { FindingCategory } from './finding.ts';
import { HARNESS, TOOL_TO_HARNESS } from './harness-map.ts';

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
 *   code_context → source_code · every other member 1:1 · anything else → custom.
 *
 * TOTAL, like toApiAction ('allowed') and toApiProvider ('api'): it returns a
 * FindingCategory for every input rather than casting an unrecognized one.
 * `config` (tooling posture) is the one DetectionCategory with no member of its
 * own and lands on 'custom'; `code_flaw` has its own member and round-trips.
 *
 * The fallback is load-bearing, not defensive. Every route returning a
 * FindingGroup / FindingInstanceDetail Zod-validates its response body on the way
 * out, and an off-enum string fails that validation for the WHOLE payload — so one
 * unmapped row 500s the entire findings page rather than degrading its own cell.
 *
 * toDbCategory inverts every member EXCEPT that fallback: filtering by 'custom'
 * matches DB 'custom' only, never the `config` rows displayed under it.
 */
export function toApiCategory(dbVal: string): FindingCategory {
  if (dbVal === 'code_context') return 'source_code';
  const parsed = FindingCategory.safeParse(dbVal);
  return parsed.success ? parsed.data : 'custom';
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
 *   github-copilot → copilot · cursor → cursor · chatgpt → chatgpt ·
 *   claude-ai → claudeai · codex → codex · antigravity → antigravity · else → api
 */
export function toApiProvider(sourceTool: string): FindingProvider {
  // Shares the single TOOL_TO_HARNESS table (harness-map.ts) with
  // `harnessFromTool`. The table's value type is `Harness & FindingProvider`,
  // so every mapped value is a FindingProvider by construction — no cast. An
  // unknown tool falls back to 'api' (whereas harnessFromTool passes it through).
  return TOOL_TO_HARNESS[sourceTool] ?? HARNESS.Api;
}

/**
 * API FindingProvider → DB sourceTool filter values (string[]).
 * claudecode and claudedesktop must never be merged. 'api' → [] (matches any
 * unknown value; the filter is applied in-memory).
 *
 * DERIVED as the inverse of the same TOOL_TO_HARNESS table `toApiProvider`
 * reads forward, so the two directions cannot disagree about which wire ids
 * belong to a provider — a tool added to that table is carried here with no
 * second edit.
 *
 * What deriving GIVES UP is the one thing a keyed table checks: that every
 * provider has a row at all. A provider no tool maps onto returns [] rather than
 * failing to compile, and [] is indistinguishable from 'api''s own contract
 * below — so it reads as the miss bucket rather than as a filter matching
 * nothing, which is a silently empty findings page instead of an error. Nothing
 * in the type system replaces that; the set assertion in harness-map.test.ts is
 * what covers it. 'api' falls out with no rows of its own, which is correct — it
 * is the miss bucket and names no single stored value.
 */
export function toDbProviderFilter(apiProvider: FindingProvider): string[] {
  return Object.entries(TOOL_TO_HARNESS)
    .filter(([, harness]) => harness === apiProvider)
    .map(([sourceTool]) => sourceTool);
}

// ─── Grouping ────────────────────────────────────────────────────────────────

/**
 * A finding row (a finding joined with its parent event), the input to the
 * instance-level build. Callers project their storage rows onto this shape:
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
  // Host tool that produced the scanned text (event metadata's toolName).
  // Optional/absent when the event carries none (legacy rows and non-tool
  // captures); file-attributed tool captures carry it alongside `file`.
  toolName?: string;
  // Lifecycle status (see FindingStatus in finding.ts). Stored 1:1 with the
  // FindingStatus values (no DB↔API translation, unlike actionTaken/category —
  // see resolutions.ts). Optional/absent for legacy rows that predate the
  // resolution feature.
  status?: FindingStatus;
  // The audit event the finding was captured from, and that event's session
  // when it has one. Optional/absent for callers that do not project them.
  eventId?: string;
  sessionId?: string;
  // Who the event is attributed to. Optional/absent for a single-user store,
  // which has no one to attribute a finding to.
  user?: FindingUser;
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
 * open-dominates precedence (see STATUS_PRECEDENCE). Statuses that are absent
 * are ignored; if NO instance carries a status, returns undefined (never
 * fabricates a status for legacy rows).
 */
export function foldGroupStatus(
  instanceStatuses: (FindingStatus | undefined)[],
): FindingStatus | undefined {
  const statuses = new Set(instanceStatuses.filter((s): s is FindingStatus => s !== undefined));
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

/** A stable order for a store-supplied user list: by label, then id. */
function sortUsers(users: FindingUser[]): FindingUser[] {
  return [...users].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

/**
 * A group's folds computed over ALL of its instances by the caller's store
 * (SQL-side aggregation), for stores too large to group row-by-row in memory.
 *
 * When an aggregate is supplied for a ruleId, `rows` may carry only a bounded
 * PREVIEW of that group's newest instances: the preview still populates
 * `instances`, but every fold that must see the whole group — instanceCount,
 * providers, aggregateAction, status, latestDetectedAt, users, and the
 * free-text haystack — is derived from the aggregate instead.
 *
 * The raw DB values are passed through UNMAPPED (sourceTools, actionsTaken,
 * statusInputs) and translated here by the same mappers the row path uses, so
 * SQL never restates an enum mapping and the two paths cannot drift.
 */
export interface FindingGroupAggregate {
  /** Exact instance count across ALL instances, not just the preview. */
  instanceCount: number;
  /**
   * The rule's severity, as the raw DB value.
   *
   * A property of the RULE rather than of any finding — every finding of one
   * rule shares it — so a store's `GROUP BY rule_id` carries it for free. It
   * lives here rather than being read off a row because the type-level build
   * has no rows at all: see buildFindingTypes.
   */
  severity?: string;
  /** The rule's category, as the raw DB value. Per-rule, exactly as `severity`. */
  category?: string;
  /** Distinct raw event.sourceTool values across ALL instances. */
  sourceTools: string[];
  /** Distinct raw findings.action_taken values across ALL instances. */
  actionsTaken: string[];
  /**
   * deriveFindingStatus inputs, one per distinct combination in the group.
   * `count` is how many instances carry that combination — it powers
   * countInstancesByStatus (status-scoped totals). Optional so callers that
   * don't track counts keep compiling; without it the status-scoped count
   * falls back to the whole-group instanceCount.
   */
  statusInputs: {
    kind: string;
    findingKey: string | null;
    latestResolutionStatus: string | null;
    count?: number;
  }[];
  /** Max occurredAt (ISO) across ALL instances. */
  latestDetectedAt: string;
  /**
   * The distinct people across ALL instances, already resolved to display
   * labels by the store. Optional: a store that attributes findings to no one
   * leaves it out, and the group then carries no `users` at all — never a fold
   * over the preview rows, which would name the preview's people as the
   * group's.
   */
  users?: FindingUser[];
  /**
   * Instance-level free text (the group's distinct repos/files/toolNames)
   * across ALL instances, folded into the search haystack so `q` still matches
   * a group whose only hit sits outside the preview.
   *
   * REQUIRED whenever the caller goes on to filter by `q`: left out, the
   * haystack falls back to the preview and a `q` matching only a buried
   * instance silently misses. Omit it only for a request with no `q` — it is
   * the one aggregate whose size tracks the store rather than the rule count.
   *
   * Instance IDs are deliberately NOT included (repos/files only). A `q` that
   * is a raw finding id therefore reaches only the preview's instances, unlike
   * the row path, which folds every instance's id into the haystack.
   */
  searchText?: string;
}

export interface BuildFindingTypesOptions {
  /** ruleId → pack display name. Absent ⇒ detection.name is null. */
  packNames?: Map<string, string>;
}

/**
 * Whole-group aggregates → FindingTypeSummary[], one per ruleId.
 *
 * There are no rows. Every field is folded by the caller's store in SQL and
 * arrives on the aggregate, which is the whole point: answering "which rules
 * are firing" costs one `GROUP BY rule_id` and never materializes a finding.
 * The read that shows a type's findings is a separate, keyset-paged instance
 * query scoped to `subtype: [id]`, so no per-type cap bounds what a reader can
 * reach.
 *
 * The raw DB values arrive UNMAPPED (sourceTools, actionsTaken, statusInputs,
 * severity, category) and are translated here by the same mappers every other
 * path uses, so SQL never restates an enum mapping.
 *
 * Iteration order is the map's own; callers sort with sortFindingTypes.
 */
export function buildFindingTypes(
  aggregates: ReadonlyMap<string, FindingGroupAggregate>,
  opts: BuildFindingTypesOptions = {},
): FindingTypeSummary[] {
  const packNames = opts.packNames;
  const types: FindingTypeSummary[] = [];

  for (const [ruleId, agg] of aggregates) {
    // Sorted for the same reason providers are: a store's own dedup order need
    // not be stable between identical requests, and cells render in array order.
    const users = sortUsers(agg.users ?? []);

    // Several source tools can fold onto one provider ('api'), so dedup after
    // mapping, then sort — a set that reshuffles per request would flap the chips.
    const providers = [...new Set(agg.sourceTools.map(toApiProvider))].sort();

    // Distinct actions, then aggregateAction: uniform → value; mixed → null.
    const actionSet = new Set(agg.actionsTaken.map(toApiAction));
    const aggregateAction = actionSet.size === 1 ? ([...actionSet][0] ?? null) : null;

    // policy: synthesized by category — id = `category:{apiCategory}`, name =
    // apiCategory display string (findings have no FK to a specific policy yet).
    const apiCategory = toApiCategory(agg.category ?? 'custom');

    const type: FindingTypeSummary = {
      id: ruleId,
      category: apiCategory,
      subtype: ruleId, // human label comes with pack metadata later
      severity: (agg.severity ?? 'low') as Severity,
      detection: { id: ruleId, name: packNames?.get(ruleId) ?? null },
      policy: { id: `category:${apiCategory}`, name: apiCategory },
      instanceCount: agg.instanceCount,
      providers,
      aggregateAction,
      latestDetectedAt: agg.latestDetectedAt,
      status: foldGroupStatus(agg.statusInputs.map(deriveFindingStatus)),
      ...(users.length > 0 ? { users } : {}),
    };

    // Prime the whole-group caches while the aggregate is in hand: neither the
    // free text nor the action set can be recovered from the built summary
    // alone (see typeHaystack / typeActions). A store that skips searchText (no
    // `q` to answer) leaves the haystack cold rather than priming one nothing
    // will read.
    actionsCache.set(type, [...actionSet]);
    if (agg.searchText !== undefined) {
      haystackCache.set(type, buildHaystack(type, agg.searchText));
    }

    types.push(type);
  }

  return types;
}

// ─── Filtering ───────────────────────────────────────────────────────────────

export interface FindingFilterOptions {
  // `| undefined` (not just optional) so callers may pass a field through
  // explicitly as undefined under exactOptionalPropertyTypes.
  severity?: string[] | undefined;
  providers?: string[] | undefined;
  actions?: string[] | undefined;
  statuses?: string[] | undefined;
  q?: string | undefined;
  subtype?: string[] | undefined;
}

// The lowercased free-text haystack for a type is immutable once the type is
// built, but applyFindingFilters runs several times per request (once per facet
// dimension in computeFindingFacets, plus the final filtered set). Memoise it
// per object so the join/lowercase happens once instead of once per pass.
// Keyed weakly so entries are collected with the request that produced them (no
// cross-request leak).
const haystackCache = new WeakMap<FindingTypeSummary, string>();

/**
 * The searchable text of a type: subtype, category, policy name and id, plus
 * `extra` — the store's whole-type instance text (distinct repos/files/toolNames;
 * see FindingGroupAggregate.searchText), which buildFindingTypes primes the
 * cache with. A toolName is folded there as its display label ("via Bash") so a
 * `q` for it matches exactly what the Locations column shows — the bare name
 * alone would collide with file paths (q "Read" hitting every README).
 *
 * This is the ONE definition of what `q` matches on the types list. It reaches
 * no finding-level text of its own: a type carries no instances and no masked
 * value, so a `q` for a masked fragment or a raw finding id is answered by the
 * INSTANCE read (rowHaystack in findings-flat-build.ts), not here.
 */
function buildHaystack(t: FindingTypeSummary, extra?: string): string {
  return [
    t.subtype,
    t.category,
    t.policy.name,
    t.id,
    ...(t.users ?? []).map((u) => u.name),
    ...(extra === undefined ? [] : [extra]),
  ]
    .join(' ')
    .toLowerCase();
}

function typeHaystack(t: FindingTypeSummary): string {
  const cached = haystackCache.get(t);
  if (cached !== undefined) return cached;
  const haystack = buildHaystack(t);
  haystackCache.set(t, haystack);
  return haystack;
}

// The type's distinct actions, primed by buildFindingTypes from the store's
// aggregate. Cached for the same reason as haystackCache: filtering runs several
// times per request. A summary carries no instances, so an unprimed entry has
// nothing to fold and reports none — which only happens for a hand-built summary
// in a test, never for one this module produced.
const actionsCache = new WeakMap<FindingTypeSummary, FindingAction[]>();

function typeActions(t: FindingTypeSummary): FindingAction[] {
  return actionsCache.get(t) ?? [];
}

/**
 * Instances in `statusInputs` whose DERIVED status is among `statuses` —
 * the status-scoped complement of a group's whole-group instanceCount, so a
 * status-filtered response can report how many instances actually carry a
 * requested status rather than the group's full tally.
 *
 * Returns null when any entry lacks a `count` (a caller that doesn't track
 * per-combination counts) — the caller falls back to the unscoped count
 * rather than reporting a partial sum as exact.
 */
export function countInstancesByStatus(
  statusInputs: FindingGroupAggregate['statusInputs'],
  statuses: readonly string[],
): number | null {
  const statusSet = new Set(statuses);
  let sum = 0;
  for (const input of statusInputs) {
    if (input.count === undefined) return null;
    if (statusSet.has(deriveFindingStatus(input))) sum += input.count;
  }
  return sum;
}

export function applyFindingFilters(
  types: FindingTypeSummary[],
  opts: FindingFilterOptions,
): FindingTypeSummary[] {
  let filtered = types;

  if (opts.severity && opts.severity.length > 0) {
    const sevSet = new Set(opts.severity);
    filtered = filtered.filter((g) => sevSet.has(g.severity));
  }

  // Provider: keep types with at least one finding on a matching provider.
  if (opts.providers && opts.providers.length > 0) {
    const providerSet = new Set(opts.providers);
    filtered = filtered.filter((g) => g.providers.some((p) => providerSet.has(p)));
  }

  // Action: keep types where at least one finding has a matching action.
  if (opts.actions && opts.actions.length > 0) {
    const actionSet = new Set(opts.actions);
    filtered = filtered.filter((t) => typeActions(t).some((a) => actionSet.has(a)));
  }

  if (opts.subtype && opts.subtype.length > 0) {
    const subtypeSet = new Set(opts.subtype);
    filtered = filtered.filter((g) => subtypeSet.has(g.subtype));
  }

  // Status: matches the TYPE's folded status (see foldGroupStatus), not "any
  // finding matches" as provider/action do — the status shown is exactly this
  // one value, so a filtered row always reads a requested status. The undefined
  // guard is defensive for callers whose aggregate carries no statuses (the
  // field is optional in the contract); the SQLite store derives a status for
  // every finding, so its types always carry one.
  if (opts.statuses && opts.statuses.length > 0) {
    const statusSet = new Set(opts.statuses);
    filtered = filtered.filter((g) => g.status !== undefined && statusSet.has(g.status));
  }

  // q: case-insensitive substring over the type's cached search haystack
  // (subtype, category, policy name, id and the store's whole-type repo/file/
  // toolName text) — see typeHaystack.
  if (opts.q) {
    const q = opts.q.toLowerCase();
    filtered = filtered.filter((t) => typeHaystack(t).includes(q));
  }

  return filtered;
}

// ─── Sorting ─────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
// Partial map so lookups on unexpected DB values return undefined (→ fallback
// -1) rather than a type-error-suppressed gap; keeps sort deterministic.
const SEVERITY_RANK = SEVERITY_ORDER as Partial<Record<string, number>>;

/**
 * The findings list's sort order: severity rank, then most recent, then id.
 *
 * The id tie-break makes the order TOTAL. Two types can legitimately share a
 * severity and a latestDetectedAt, and without a third key their relative order
 * is whatever the sort happened to produce — which a keyset cursor cannot
 * resume from, because "everything after this one" is then ambiguous. Only
 * types tied on both other keys are affected.
 *
 * Takes the fields it compares rather than a whole summary so a cursor can be
 * compared against the list without being inflated into one.
 */
export function compareFindingGroupOrder(
  a: Pick<FindingTypeSummary, 'severity' | 'latestDetectedAt' | 'id'>,
  b: Pick<FindingTypeSummary, 'severity' | 'latestDetectedAt' | 'id'>,
): number {
  const rankA = SEVERITY_RANK[a.severity] ?? -1;
  const rankB = SEVERITY_RANK[b.severity] ?? -1;
  const severityDiff = rankA - rankB;
  if (severityDiff !== 0) return severityDiff;
  // latestDetectedAt desc — ISO strings sort lexically.
  const recencyDiff = b.latestDetectedAt.localeCompare(a.latestDetectedAt);
  if (recencyDiff !== 0) return recencyDiff;
  return a.id.localeCompare(b.id);
}

export function sortFindingTypes(types: FindingTypeSummary[]): FindingTypeSummary[] {
  return [...types].sort(compareFindingGroupOrder);
}

// ─── Facets (per-filter-excluded counts) ─────────────────────────────────────

/**
 * Per-dimension facet counts, each computed by applying all filters EXCEPT that
 * dimension's own — so "how many types if I also pick X?" stays answerable.
 *
 * Counts TYPES, which is the unit this list pages. The instance read computes
 * its own facets over findings; a surface showing both states which is which.
 */
export function computeFindingFacets(
  allTypes: FindingTypeSummary[],
  opts: FindingFilterOptions,
): FindingFacets {
  const forSeverity = applyFindingFilters(allTypes, {
    providers: opts.providers,
    actions: opts.actions,
    statuses: opts.statuses,
    q: opts.q,
    subtype: opts.subtype,
  });
  const severityMap = new Map<string, number>();
  for (const g of forSeverity) {
    severityMap.set(g.severity, (severityMap.get(g.severity) ?? 0) + 1);
  }

  const forProvider = applyFindingFilters(allTypes, {
    actions: opts.actions,
    statuses: opts.statuses,
    q: opts.q,
    subtype: opts.subtype,
    severity: opts.severity,
  });
  const providerMap = new Map<string, number>();
  for (const g of forProvider) {
    for (const p of g.providers) providerMap.set(p, (providerMap.get(p) ?? 0) + 1);
  }

  const forAction = applyFindingFilters(allTypes, {
    providers: opts.providers,
    statuses: opts.statuses,
    q: opts.q,
    subtype: opts.subtype,
    severity: opts.severity,
  });
  const actionMap = new Map<string, number>();
  for (const g of forAction) {
    for (const a of typeActions(g)) actionMap.set(a, (actionMap.get(a) ?? 0) + 1);
  }

  const forSubtype = applyFindingFilters(allTypes, {
    providers: opts.providers,
    actions: opts.actions,
    statuses: opts.statuses,
    q: opts.q,
    severity: opts.severity,
  });
  const subtypeMap = new Map<string, number>();
  for (const g of forSubtype) subtypeMap.set(g.subtype, (subtypeMap.get(g.subtype) ?? 0) + 1);

  // A status-less type (possible only for callers whose aggregate carries no
  // statuses — the SQLite store always derives one) contributes to no bucket:
  // the filter can't select it either, so a count it can never reach would
  // misstate the dimension.
  const forStatus = applyFindingFilters(allTypes, {
    providers: opts.providers,
    actions: opts.actions,
    q: opts.q,
    subtype: opts.subtype,
    severity: opts.severity,
  });
  const statusMap = new Map<string, number>();
  for (const g of forStatus) {
    if (g.status !== undefined) statusMap.set(g.status, (statusMap.get(g.status) ?? 0) + 1);
  }

  const toItems = (m: Map<string, number>): FindingFacetItem[] =>
    [...m.entries()].map(([value, count]) => ({ value, count }));

  return {
    severity: toItems(severityMap),
    provider: toItems(providerMap),
    action: toItems(actionMap),
    subtype: toItems(subtypeMap),
    status: toItems(statusMap),
  };
}
