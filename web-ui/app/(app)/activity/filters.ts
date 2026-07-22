import {
  DEFAULT_TIME_RANGE,
  parseTimeRange,
  rangeToFromIso,
  type TimeRange,
} from '@akasecurity/dashboard-ui';
import { Harness, type ListActivitySessionsQuery } from '@akasecurity/schema';

// The Activity list state rides in the URL (?q=&harness=&harness=&range=&id=&empty=1)
// so the Server Component re-queries the local store on every change — the same
// mechanism as the findings/detections pages. These pure helpers convert between
// the URL params and the persistence query; shared by the page (parse) and the
// client shell (build), so keep it dependency-free of React.

type ParamValue = string | string[] | undefined;
export type ActivitySearchParams = Record<string, ParamValue>;

const asArray = (v: ParamValue): string[] => (Array.isArray(v) ? v : v ? [v] : []);
const one = (v: ParamValue): string => (Array.isArray(v) ? (v[0] ?? '') : (v ?? ''));

/** The single search term, trimmed (kept in sync with buildActivityParams). */
export function parseQuery(sp: ActivitySearchParams): string {
  return one(sp.q).trim();
}

/**
 * URL ?harness values → the multi-select, validated against the schema enum here
 * (the OSS Server-Component path has no Fastify/Zod door), so a crafted
 * `?harness=bogus` is dropped rather than passed to the store.
 */
export function parseHarness(sp: ActivitySearchParams): Harness[] {
  return asArray(sp.harness).filter((v): v is Harness =>
    (Harness.options as readonly string[]).includes(v),
  );
}

/** The selected session id, or '' when none is pinned. */
export function parseSelectedId(sp: ActivitySearchParams): string {
  return one(sp.id).trim();
}

/** The time-range chip value, defaulting/validating via the shared range parser. */
export function parseActivityRange(sp: ActivitySearchParams): TimeRange {
  return parseTimeRange(one(sp.range));
}

/** Whether zero-activity ("background") sessions are shown — hidden by default;
 * `?empty=1` reveals them. */
export function parseShowEmpty(sp: ActivitySearchParams): boolean {
  return one(sp.empty) === '1';
}

/**
 * Search + harness + range → the persistence session-list query. The range maps
 * to a `from` lower bound (`now − N days`); `limit: 100` is the schema max (the
 * list shows a truncation notice past it rather than paginating). `nowMs` is
 * injectable so the derived `from` is testable.
 */
export function toListQuery(
  q: string,
  harness: Harness[],
  range: TimeRange,
  showEmpty = false,
  nowMs: number = Date.now(),
): ListActivitySessionsQuery {
  return {
    ...(q ? { q } : {}),
    ...(harness.length ? { harness } : {}),
    // Zero-activity sessions are hidden unless the toggle reveals them.
    ...(showEmpty ? {} : { excludeEmpty: true }),
    from: rangeToFromIso(range, nowMs),
    limit: 100,
  };
}

/** Current list state → a URLSearchParams for router.push (omit defaults/blanks). */
export function buildActivityParams(opts: {
  q: string;
  harness: Harness[];
  range: TimeRange;
  id?: string;
  showEmpty?: boolean;
}): URLSearchParams {
  const sp = new URLSearchParams();
  const q = opts.q.trim();
  if (q) sp.set('q', q);
  for (const h of opts.harness) sp.append('harness', h);
  // Omit only the actual default (what parseTimeRange returns for a missing param),
  // else a non-default range like 30d gets dropped and the next server render
  // resets it to DEFAULT_TIME_RANGE.
  if (opts.range !== DEFAULT_TIME_RANGE) sp.set('range', opts.range);
  if (opts.id) sp.set('id', opts.id);
  if (opts.showEmpty) sp.set('empty', '1');
  return sp;
}
