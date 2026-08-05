import {
  DEFAULT_FINDINGS_VIEW,
  type FindingsFilters,
  type FindingsView,
  isFindingsView,
} from '@akasecurity/dashboard-ui';
import {
  FindingAction,
  FindingProvider,
  FindingStatus,
  type ListFindingInstancesQuery,
  type ListFindingLocationsQuery,
  type ListGroupedFindingsQuery,
  Severity,
  TimeRange,
} from '@akasecurity/schema';

// The findings filters ride in the URL (?severity=…&type=…&provider=…&action=…&status=…&q=…,
// plus the Activity page's deep-link context: ?session=… scopes the list to one
// session and ?finding=… opens the detail sheet) so the Server Component re-queries
// the local store per filter change — the same mechanism as RangeSelect. These pure
// helpers convert between the URL params, the toolbar's FindingsFilters shape, and
// the persistence query. Shared by the page (parse + query) and the client wrapper
// (build params), so keep it dependency-free.

/** Next's searchParams value for one key: absent, a single value, or repeated. */
type ParamValue = string | string[] | undefined;
export type FindingsSearchParams = Record<string, ParamValue>;

const asArray = (v: ParamValue): string[] => (Array.isArray(v) ? v : v ? [v] : []);

/**
 * Drop values not in the enum and dedupe — hand-edited/stale URLs can't inject
 * unknowns, and a double-appended value (?status=open&status=open) can't make
 * the toolbar badge count one selection twice.
 */
const keepKnown = (values: string[], allowed: readonly string[]): string[] =>
  [...new Set(values)].filter((v) => allowed.includes(v));

/**
 * URL search params → the toolbar's five filter dimensions. Severity/provider/
 * action/status are validated against their schema enums here (the OSS
 * Server-Component path has no Fastify/Zod validation door), so a crafted
 * `?severity=bogus` is dropped rather than passed on to the store.
 * `type`/subtype is a free string.
 */
export function parseFindingsFilters(sp: FindingsSearchParams): FindingsFilters {
  return {
    severity: keepKnown(asArray(sp.severity), Severity.options),
    // Free string, so no enum check — but deduped for the same badge-count
    // reason as keepKnown.
    type: [...new Set(asArray(sp.type))],
    provider: keepKnown(asArray(sp.provider), FindingProvider.options),
    action: keepKnown(asArray(sp.action), FindingAction.options),
    status: keepKnown(asArray(sp.status), FindingStatus.options),
  };
}

/**
 * The single search term, trimmed of surrounding whitespace. Trimming here keeps
 * the parsed value in sync with buildFindingsParams (which writes the trimmed
 * term to the URL) — otherwise the client's debounced `query` state could never
 * settle to `initialQuery` and would re-push forever (see FindingsClient).
 */
export function parseQuery(sp: FindingsSearchParams): string {
  return typeof sp.q === 'string' ? sp.q.trim() : '';
}

/** The session id the list is scoped to (?session=…), or '' when unscoped. */
export function parseSession(sp: FindingsSearchParams): string {
  return typeof sp.session === 'string' ? sp.session.trim() : '';
}

/**
 * Which view the list renders (?view=). An absent or unknown value is the
 * grouped default — a hand-edited URL must not produce a blank page.
 */
export function parseView(sp: FindingsSearchParams): FindingsView {
  const raw = typeof sp.view === 'string' ? sp.view.trim() : '';
  return isFindingsView(raw) ? raw : DEFAULT_FINDINGS_VIEW;
}

/**
 * Exact host-tool names (?tool=, repeatable). A real filter, unlike `q`, which
 * can only match the rendered "via Bash" label. Free strings (tool names come
 * from the host, not an enum), so deduped rather than enum-checked.
 */
export function parseTools(sp: FindingsSearchParams): string[] {
  return [...new Set(asArray(sp.tool))];
}

/** The repo (?repo=) and file (?file=) drill-down from the locations view. */
export function parseRepo(sp: FindingsSearchParams): string {
  return typeof sp.repo === 'string' ? sp.repo.trim() : '';
}

export function parseFile(sp: FindingsSearchParams): string {
  return typeof sp.file === 'string' ? sp.file.trim() : '';
}

/**
 * The time window (?range=). Parsed with safeParse so an absent or unknown
 * value means ALL TIME: this list has never had a default window, and silently
 * applying one would hide findings a reader has no way to know are missing.
 */
export function parseRange(sp: FindingsSearchParams): TimeRange | null {
  const raw = typeof sp.range === 'string' ? sp.range.trim() : '';
  const parsed = TimeRange.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

/** The finding (group or instance) id the detail sheet opens on (?finding=…). */
export function parseSelectedFinding(sp: FindingsSearchParams): string {
  return typeof sp.finding === 'string' ? sp.finding.trim() : '';
}

/**
 * Filters + search → the persistence grouped-findings query. The filter arrays
 * carry validated enum values (the toolbar only emits facet/severity values, and
 * parseFindingsFilters drops unknown URL values), so the casts to the schema
 * enums are safe.
 */
export function toGroupedQuery(
  filters: FindingsFilters,
  q: string,
  session = '',
  scope: FindingsScope = {},
): ListGroupedFindingsQuery {
  const trimmed = q.trim();
  // `tool`, `repo` and `file` are deliberately NOT carried: they are
  // per-instance filters, and a group spans instances. Switching to the
  // grouped view drops them, which the view toggle states rather than hides.
  return {
    ...(filters.severity.length ? { severity: filters.severity as Severity[] } : {}),
    ...(filters.type.length ? { subtype: filters.type } : {}),
    ...(filters.provider.length ? { provider: filters.provider as FindingProvider[] } : {}),
    ...(filters.action.length ? { action: filters.action as FindingAction[] } : {}),
    ...(filters.status.length ? { status: filters.status as FindingStatus[] } : {}),
    ...(trimmed ? { q: trimmed } : {}),
    ...(session ? { sessionId: session } : {}),
    ...(scope.from ? { from: scope.from } : {}),
  };
}

/**
 * The scope a query carries beyond the toolbar's own dimensions: the resolved
 * time bound, and the locations view's drill-down.
 */
export interface FindingsScope {
  from?: string | undefined;
  tools?: string[] | undefined;
  repo?: string | undefined;
  file?: string | undefined;
}

/** Filters + search → the instance-level (flat) query. */
export function toInstancesQuery(
  filters: FindingsFilters,
  q: string,
  session = '',
  scope: FindingsScope = {},
): ListFindingInstancesQuery {
  const trimmed = q.trim();
  return {
    ...(filters.severity.length ? { severity: filters.severity as Severity[] } : {}),
    ...(filters.type.length ? { subtype: filters.type } : {}),
    ...(filters.provider.length ? { provider: filters.provider as FindingProvider[] } : {}),
    ...(filters.action.length ? { action: filters.action as FindingAction[] } : {}),
    ...(filters.status.length ? { status: filters.status as FindingStatus[] } : {}),
    ...(trimmed ? { q: trimmed } : {}),
    ...(session ? { sessionId: session } : {}),
    ...(scope.from ? { from: scope.from } : {}),
    ...(scope.tools?.length ? { tool: scope.tools } : {}),
    ...(scope.repo ? { repo: scope.repo } : {}),
    ...(scope.file ? { file: scope.file } : {}),
  };
}

/**
 * Filters + search → the locations query. `repo`/`file` are absent by design:
 * this view IS the repo/file breakdown, so narrowing it to one would leave a
 * tree of exactly one node.
 */
export function toLocationsQuery(
  filters: FindingsFilters,
  q: string,
  session = '',
  scope: FindingsScope = {},
): ListFindingLocationsQuery {
  const trimmed = q.trim();
  return {
    ...(filters.severity.length ? { severity: filters.severity as Severity[] } : {}),
    ...(filters.type.length ? { subtype: filters.type } : {}),
    ...(filters.provider.length ? { provider: filters.provider as FindingProvider[] } : {}),
    ...(filters.action.length ? { action: filters.action as FindingAction[] } : {}),
    ...(filters.status.length ? { status: filters.status as FindingStatus[] } : {}),
    ...(trimmed ? { q: trimmed } : {}),
    ...(session ? { sessionId: session } : {}),
    ...(scope.from ? { from: scope.from } : {}),
    ...(scope.tools?.length ? { tool: scope.tools } : {}),
  };
}

/**
 * The toolbar's filters + search → a URLSearchParams (repeated keys per value).
 * The session scope rides along so filter/search changes keep the deep-link
 * context; the `finding` selection param is deliberately NOT rebuilt here — it
 * is a one-shot deep link, dropped as soon as the user navigates.
 */
export function buildFindingsParams(
  filters: FindingsFilters,
  q: string,
  session = '',
  url: FindingsUrlState = {},
): URLSearchParams {
  const sp = new URLSearchParams();
  for (const s of filters.severity) sp.append('severity', s);
  for (const t of filters.type) sp.append('type', t);
  for (const p of filters.provider) sp.append('provider', p);
  for (const a of filters.action) sp.append('action', a);
  for (const s of filters.status) sp.append('status', s);
  const trimmed = q.trim();
  if (trimmed) sp.set('q', trimmed);
  if (session) sp.set('session', session);

  // The default view writes no param, so the plain findings URL stays clean.
  if (url.view && url.view !== DEFAULT_FINDINGS_VIEW) sp.set('view', url.view);
  if (url.range) sp.set('range', url.range);
  // The instance-level filters exist only where a view can honor them. Writing
  // them under `grouped` would leave a param the page silently ignores, which
  // survives into a shared link and reads as a filter that stopped working.
  if (url.view === 'flat' || url.view === 'files') {
    for (const t of url.tools ?? []) sp.append('tool', t);
  }
  if (url.view === 'flat') {
    if (url.repo) sp.set('repo', url.repo);
    if (url.file) sp.set('file', url.file);
  }
  return sp;
}

/** The URL state beyond the toolbar filters, search and session scope. */
export interface FindingsUrlState {
  view?: FindingsView | undefined;
  range?: TimeRange | null | undefined;
  tools?: string[] | undefined;
  repo?: string | undefined;
  file?: string | undefined;
}
