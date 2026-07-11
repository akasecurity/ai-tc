import type { FindingsFilters } from '@akasecurity/dashboard-ui';
import {
  FindingAction,
  FindingProvider,
  type ListGroupedFindingsQuery,
  Severity,
} from '@akasecurity/schema';

// The findings filters ride in the URL (?severity=…&type=…&provider=…&action=…&q=…)
// so the Server Component re-queries the local store per filter change — the same
// mechanism as RangeSelect. These pure helpers convert between the URL params, the
// toolbar's FindingsFilters shape, and the persistence query. Shared by the page
// (parse + query) and the client wrapper (build params), so keep it dependency-free.

/** Next's searchParams value for one key: absent, a single value, or repeated. */
type ParamValue = string | string[] | undefined;
export type FindingsSearchParams = Record<string, ParamValue>;

const asArray = (v: ParamValue): string[] => (Array.isArray(v) ? v : v ? [v] : []);

/** Drop values not in the enum — hand-edited/stale URLs can't inject unknowns. */
const keepKnown = (values: string[], allowed: readonly string[]): string[] =>
  values.filter((v) => allowed.includes(v));

/**
 * URL search params → the toolbar's four filter dimensions. Severity/provider/
 * action are validated against their schema enums here (the OSS Server-Component
 * path has no Fastify/Zod validation door), so a crafted `?severity=bogus` is
 * dropped rather than passed on to the store. `type`/subtype is a free string.
 */
export function parseFindingsFilters(sp: FindingsSearchParams): FindingsFilters {
  return {
    severity: keepKnown(asArray(sp.severity), Severity.options),
    type: asArray(sp.type),
    provider: keepKnown(asArray(sp.provider), FindingProvider.options),
    action: keepKnown(asArray(sp.action), FindingAction.options),
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

/**
 * Filters + search → the persistence grouped-findings query. The filter arrays
 * carry validated enum values (the toolbar only emits facet/severity values, and
 * parseFindingsFilters drops unknown URL values), so the casts to the schema
 * enums are safe.
 */
export function toGroupedQuery(filters: FindingsFilters, q: string): ListGroupedFindingsQuery {
  const trimmed = q.trim();
  return {
    ...(filters.severity.length ? { severity: filters.severity as Severity[] } : {}),
    ...(filters.type.length ? { subtype: filters.type } : {}),
    ...(filters.provider.length ? { provider: filters.provider as FindingProvider[] } : {}),
    ...(filters.action.length ? { action: filters.action as FindingAction[] } : {}),
    ...(trimmed ? { q: trimmed } : {}),
  };
}

/** The toolbar's filters + search → a URLSearchParams (repeated keys per value). */
export function buildFindingsParams(filters: FindingsFilters, q: string): URLSearchParams {
  const sp = new URLSearchParams();
  for (const s of filters.severity) sp.append('severity', s);
  for (const t of filters.type) sp.append('type', t);
  for (const p of filters.provider) sp.append('provider', p);
  for (const a of filters.action) sp.append('action', a);
  const trimmed = q.trim();
  if (trimmed) sp.set('q', trimmed);
  return sp;
}
