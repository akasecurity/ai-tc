import type { FindingsFilters } from '@akasecurity/dashboard-ui';
import {
  FindingAction,
  FindingProvider,
  FindingStatus,
  type ListGroupedFindingsQuery,
  Severity,
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
): ListGroupedFindingsQuery {
  const trimmed = q.trim();
  return {
    ...(filters.severity.length ? { severity: filters.severity as Severity[] } : {}),
    ...(filters.type.length ? { subtype: filters.type } : {}),
    ...(filters.provider.length ? { provider: filters.provider as FindingProvider[] } : {}),
    ...(filters.action.length ? { action: filters.action as FindingAction[] } : {}),
    ...(filters.status.length ? { status: filters.status as FindingStatus[] } : {}),
    ...(trimmed ? { q: trimmed } : {}),
    ...(session ? { sessionId: session } : {}),
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
  return sp;
}
