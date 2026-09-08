// Instance-level (flat) findings: the filtering, faceting and projection the
// grouped path does per GROUP, done per FINDING instead.
//
// This is a sibling of findings-group-build.ts, not a replacement: the two
// answer different questions and their filter semantics genuinely differ. A
// status filter here matches the instance's own derived status, where the
// grouped path matches the group's folded one; provider and action here match
// the row, where the grouped path keeps a group if ANY instance matches. Every
// DB→API translation still goes through the shared mappers, so no enum rule is
// restated.

import type {
  FindingFacetItem,
  FindingFacets,
  FindingInstanceDetail,
  FindingStatus,
} from './finding.ts';
import {
  type GroupableFindingRow,
  toApiAction,
  toApiCategory,
  toApiProvider,
} from './findings-group-build.ts';

/**
 * A GroupableFindingRow that also carries its event linkage. The flat list
 * projects one of these per finding; the grouped list's preview rows now carry
 * the same two fields, so a store can produce either from one row shape.
 */
export interface FlatFindingRow extends GroupableFindingRow {
  // Required here where the base leaves it optional: a flat row is always
  // projected from the findings⋈events join, so it always has its event.
  // `sessionId` stays optional — an event outside a session carries none.
  eventId: string;
}

export interface InstanceFilterOptions {
  // `| undefined` (not just optional) so callers may pass a field through
  // explicitly as undefined under exactOptionalPropertyTypes — the same
  // convention FindingFilterOptions follows.
  severity?: string[] | undefined;
  subtype?: string[] | undefined;
  providers?: string[] | undefined;
  actions?: string[] | undefined;
  statuses?: string[] | undefined;
  tools?: string[] | undefined;
  repo?: string | undefined;
  file?: string | undefined;
  q?: string | undefined;
}

/** The filter dimensions, so a facet pass can name the one it excludes. */
export type InstanceFilterDimension = keyof InstanceFilterOptions;

/**
 * The searchable text of one instance: rule id, category, masked value, repo,
 * file, its tool as the rendered "via Bash" label, its id, and the label of
 * the person it is attributed to (when the store attributes findings).
 * Mirrors the grouped path's haystack so the same `q` matches the same things
 * in both views — a tool searched as the bare name would collide with file
 * paths.
 */
function rowHaystack(row: FlatFindingRow): string {
  return [
    row.ruleId,
    row.category,
    row.maskedMatch,
    row.repo,
    row.file,
    row.toolName ? `via ${row.toolName}` : '',
    row.id,
    row.user?.name ?? '',
  ]
    .join(' ')
    .toLowerCase();
}

function matchesDimension(
  row: FlatFindingRow,
  opts: InstanceFilterOptions,
  dimension: InstanceFilterDimension,
): boolean {
  switch (dimension) {
    case 'severity':
      return !opts.severity?.length || opts.severity.includes(row.severity);
    case 'subtype':
      return !opts.subtype?.length || opts.subtype.includes(row.ruleId);
    case 'providers':
      return !opts.providers?.length || opts.providers.includes(toApiProvider(row.sourceTool));
    case 'actions':
      return !opts.actions?.length || opts.actions.includes(toApiAction(row.actionTaken));
    case 'statuses':
      return (
        !opts.statuses?.length || (row.status !== undefined && opts.statuses.includes(row.status))
      );
    case 'tools':
      return (
        !opts.tools?.length || (row.toolName !== undefined && opts.tools.includes(row.toolName))
      );
    // An EMPTY value is a real filter here, not an absent one. The location
    // list buckets a finding whose event recorded no repo — or no file — under
    // the empty string, and selecting that bucket has to narrow the panel to
    // exactly it. Only `undefined` means "no filter"; a caller that wants every
    // row omits the key, which every call site already does.
    //
    // Reading '' as unset is what this replaced, and it failed in the one place
    // it mattered: the no-repo/no-file bucket is often the largest in a real
    // store, and its panel dropped both predicates and returned the WHOLE scope
    // — a row reading 3 findings beside a panel listing every finding there is.
    case 'repo':
      return opts.repo === undefined || row.repo === opts.repo;
    case 'file':
      return opts.file === undefined || row.file === opts.file;
    case 'q':
      return !opts.q || rowHaystack(row).includes(opts.q.toLowerCase());
  }
}

const DIMENSIONS: readonly InstanceFilterDimension[] = [
  'severity',
  'subtype',
  'providers',
  'actions',
  'statuses',
  'tools',
  'repo',
  'file',
  'q',
];

/**
 * Whether a row passes the filters, optionally ignoring one dimension — the
 * `except` form is what lets a facet count answer "how many if I also pick X?"
 * without re-filtering the whole scope per dimension.
 */
export function matchesInstanceFilters(
  row: FlatFindingRow,
  opts: InstanceFilterOptions,
  except?: InstanceFilterDimension,
): boolean {
  for (const dimension of DIMENSIONS) {
    if (dimension === except) continue;
    if (!matchesDimension(row, opts, dimension)) return false;
  }
  return true;
}

function toItems(counts: Map<string, number>): FindingFacetItem[] {
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

function bump(counts: Map<string, number>, value: string): void {
  counts.set(value, (counts.get(value) ?? 0) + 1);
}

/**
 * Per-dimension facet counts in INSTANCES, each excluding its own filter — the
 * instance-level counterpart of computeFindingFacets.
 *
 * Streaming rather than array-based: the flat list scans its whole filtered
 * scope to produce cursor-independent totals, and holding every row to run six
 * more filter passes over them afterwards would make memory track the store.
 * One `add` per row fills every dimension.
 */
export function createInstanceFacetAccumulator(opts: InstanceFilterOptions): {
  add: (row: FlatFindingRow) => void;
  facets: () => FindingFacets;
} {
  const severity = new Map<string, number>();
  const subtype = new Map<string, number>();
  const provider = new Map<string, number>();
  const action = new Map<string, number>();
  const status = new Map<string, number>();
  const tool = new Map<string, number>();

  return {
    add(row) {
      if (matchesInstanceFilters(row, opts, 'severity')) bump(severity, row.severity);
      if (matchesInstanceFilters(row, opts, 'subtype')) bump(subtype, row.ruleId);
      if (matchesInstanceFilters(row, opts, 'providers')) {
        bump(provider, toApiProvider(row.sourceTool));
      }
      if (matchesInstanceFilters(row, opts, 'actions')) bump(action, toApiAction(row.actionTaken));
      if (row.status !== undefined && matchesInstanceFilters(row, opts, 'statuses')) {
        bump(status, row.status);
      }
      // A row with no tool contributes to no tool facet — the dimension counts
      // tools, and "no tool" is not one.
      if (row.toolName !== undefined && matchesInstanceFilters(row, opts, 'tools')) {
        bump(tool, row.toolName);
      }
    },
    facets: () => ({
      severity: toItems(severity),
      subtype: toItems(subtype),
      provider: toItems(provider),
      action: toItems(action),
      status: toItems(status),
      tool: toItems(tool),
    }),
  };
}

/**
 * One row → the denormalized instance detail the flat list renders. The group
 * context a row carries is its rule's, so `detection.name` is null and `policy`
 * is synthesized from the category, exactly as the grouped path does for the
 * local store.
 */
export function toInstanceDetail(row: FlatFindingRow): FindingInstanceDetail {
  const category = toApiCategory(row.category);
  return {
    id: row.id,
    provider: toApiProvider(row.sourceTool),
    repo: row.repo,
    file: row.file,
    ...(row.toolName === undefined ? {} : { toolName: row.toolName }),
    eventId: row.eventId,
    ...(row.sessionId === undefined ? {} : { sessionId: row.sessionId }),
    ...(row.user === undefined ? {} : { user: row.user }),
    action: toApiAction(row.actionTaken),
    detectedAt: row.occurredAt,
    confidence: row.confidence,
    ...(row.status === undefined ? {} : { status: row.status }),
    groupId: row.ruleId,
    category,
    subtype: row.ruleId,
    severity: row.severity as FindingInstanceDetail['severity'],
    match: { maskedValue: row.maskedMatch, contextPrefix: '' },
    detection: { id: row.ruleId, name: null },
    policy: { id: `category:${category}`, name: category },
  };
}

// ─── Location folding (repo → file) ──────────────────────────────────────────

/** The running fold for one location, before it becomes a response row. */
export interface LocationAccumulator {
  instanceCount: number;
  maxSeverityRank: number;
  maxSeverity: string;
  latestDetectedAt: string;
  statuses: (FindingStatus | undefined)[];
  ruleIds: Set<string>;
}

const SEVERITY_ORDER: Partial<Record<string, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function newLocationAccumulator(): LocationAccumulator {
  return {
    instanceCount: 0,
    // Sorts after every known severity, so the first row always wins the
    // comparison below rather than an unknown value pinning the location.
    maxSeverityRank: Number.MAX_SAFE_INTEGER,
    maxSeverity: 'low',
    latestDetectedAt: '',
    statuses: [],
    ruleIds: new Set(),
  };
}

export function addToLocation(acc: LocationAccumulator, row: FlatFindingRow): void {
  acc.instanceCount += 1;
  const rank = SEVERITY_ORDER[row.severity] ?? Number.MAX_SAFE_INTEGER - 1;
  if (rank < acc.maxSeverityRank) {
    acc.maxSeverityRank = rank;
    acc.maxSeverity = row.severity;
  }
  if (row.occurredAt > acc.latestDetectedAt) acc.latestDetectedAt = row.occurredAt;
  acc.statuses.push(row.status);
  acc.ruleIds.add(row.ruleId);
}

/**
 * The key a location row is ordered by, and the shape its cursor carries.
 *
 * A key rather than a whole row, for the reason compareFindingGroupOrder takes a
 * Pick: a keyset cursor has to be compared against the list without first being
 * inflated into a row it never was.
 */
export interface LocationOrderKey {
  maxSeverity: string;
  latestDetectedAt: string;
  repo: string;
  file: string;
}

/**
 * Location rows sort worst severity first, then most recent, then by (repo,
 * file) — and that last key is what makes the order TOTAL.
 *
 * Total is load-bearing rather than tidy, because this list is keyset-paged. A
 * cursor resumes at "the first row strictly after this one", so two rows the
 * comparator calls equal are two rows it cannot get between. Three locations
 * tied on both severity and instant, paged two at a time: the cursor minted from
 * the second matches nothing greater, the next page comes back EMPTY, and the
 * third location is unreachable behind a Next button that was enabled. The pair
 * is unique per location, so ordering on it removes ties outright.
 *
 * The two string keys are compared with `<` rather than `localeCompare`, which
 * is NOT interchangeable here: ICU collation reports canonically-equivalent
 * strings as equal, so a precomposed and a decomposed 'café.ts' compare 0 — and
 * macOS stores NFD where event metadata arrives NFC, which reintroduces exactly
 * the tie this key exists to remove. `<` is UTF-16 code-unit order: total,
 * locale-free, and the same in every runtime.
 *
 * They are also two SEPARATE keys rather than one joined string. Joining needs a
 * separator provably absent from arbitrary repo names and file paths, and there
 * is no such character.
 */
export function compareLocationOrder(a: LocationOrderKey, b: LocationOrderKey): number {
  // `?? -1` ranks an unknown severity BEFORE every known one, which is what
  // makes an undecodable or hand-edited cursor degrade to a restart from the top
  // rather than to an empty page — the same property decodeGroupCursor documents
  // for its own `sev`. It differs from newLocationAccumulator's miss value on
  // purpose: that one is picking a maximum and must lose every comparison, this
  // one is ordering and must not bucket an unknown value among the known ones.
  const rankA = SEVERITY_ORDER[a.maxSeverity] ?? -1;
  const rankB = SEVERITY_ORDER[b.maxSeverity] ?? -1;
  if (rankA !== rankB) return rankA - rankB;
  // latestDetectedAt descending — ISO-8601 strings sort lexically.
  if (a.latestDetectedAt !== b.latestDetectedAt) {
    return a.latestDetectedAt < b.latestDetectedAt ? 1 : -1;
  }
  if (a.repo !== b.repo) return a.repo < b.repo ? -1 : 1;
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return 0;
}

/**
 * The opaque id a location row carries, minted from the pair that identifies it.
 *
 * A location's identity is (repo, file) and a URL param holds one value, so
 * `?loc=` needs the two folded into a single token — the way `?rule=` names a
 * type by its one id. Both halves are percent-encoded, so the separator cannot
 * occur inside either and the single literal '/' left is unambiguous. The empty
 * pair therefore mints '/' rather than '', which is what keeps
 * present-and-empty distinguishable from absent and makes the no-repo/no-file
 * bucket selectable at all.
 *
 * Deliberately not a base64 encode: this package takes no Node-API dependency
 * (it is reachable from the browser-side bundle), so there is no Buffer to reach
 * for, and btoa is latin1-only and would corrupt a non-ASCII path.
 *
 * Deliberately not a sort key either — see compareLocationOrder, which orders on
 * the pair itself. This token is only ever compared for EQUALITY: the page's
 * selection check, the read's includeId, and the client's page dedupe.
 */
export function encodeLocationId(repo: string, file: string): string {
  return `${encodePart(repo)}/${encodePart(file)}`;
}

/**
 * One half of a location id, percent-encoded — and never throwing.
 *
 * `encodeURIComponent` raises URIError on a LONE SURROGATE, and event metadata
 * reaches the store as JSON, where a `\uD800` escape parses into exactly that.
 * One such path would otherwise take out the whole locations read while it
 * projected its rows: not that row, the entire page, under every filter. Nothing
 * else on this path fails that way.
 *
 * A lone surrogate is replaced with U+FFFD before encoding. That is lossy, and
 * safely so — the id is compared only for equality and is derived
 * deterministically from the pair on both sides of every comparison, so two
 * locations still collide only if their paths already differ nowhere but in an
 * unpaired surrogate. The repo and file the row DISPLAYS are untouched.
 */
function encodePart(value: string): string {
  // The `u` flag is what makes this narrow, and it is the whole trick: under
  // Unicode mode the pattern matches code POINTS, and a valid surrogate pair is
  // one code point outside this range — so only UNPAIRED surrogates match. Drop
  // the flag and the same class matches both halves of every astral character,
  // collapsing every emoji-bearing path onto one id. Hand-rolled lookarounds for
  // "a high surrogate not followed by a low one" are the same thing spelled out,
  // and buy nothing.
  return encodeURIComponent(value.replace(/[\uD800-\uDFFF]/gu, '\uFFFD'));
}
