import type { ListDetectionsQuery } from '@akasecurity/schema';

// The detections list state rides in the URL (?filter=…&q=…&id=…) so the Server
// Component re-queries the local store on every change — the same mechanism as the
// findings/security pages. These pure helpers convert between the URL params and
// the persistence query; shared by the page (parse) and the client wrapper (build).

type ParamValue = string | string[] | undefined;
export type DetectionsSearchParams = Record<string, ParamValue>;

const one = (v: ParamValue): string => (Array.isArray(v) ? (v[0] ?? '') : (v ?? ''));

// Updates come from the available_packs mirror (the inventory the running
// plugin/CLI ships), so the `updates` tab is fully local; there is no local
// custom/customized rule model, so no filters for those.
export const OSS_DETECTION_FILTERS = ['all', 'library', 'updates'] as const;
export type OssDetectionFilter = (typeof OSS_DETECTION_FILTERS)[number];

/** URL ?filter → an OSS filter, dropping unknown/unsupported values to `all`. */
export function parseDetectionFilter(sp: DetectionsSearchParams): OssDetectionFilter {
  const f = one(sp.filter);
  return (OSS_DETECTION_FILTERS as readonly string[]).includes(f)
    ? (f as OssDetectionFilter)
    : 'all';
}

/** The single search term, trimmed (kept in sync with buildDetectionsParams). */
export function parseDetectionQuery(sp: DetectionsSearchParams): string {
  return one(sp.q).trim();
}

/** The selected detection id ("namespace/packId"), or '' when none is pinned. */
export function parseSelectedId(sp: DetectionsSearchParams): string {
  return one(sp.id).trim();
}

/** Filter + search → the persistence list query (omit `q` when blank). */
export function toListQuery(filter: OssDetectionFilter, q: string): ListDetectionsQuery {
  const trimmed = q.trim();
  return { filter, ...(trimmed ? { q: trimmed } : {}) };
}

/** Current list state → a URLSearchParams for router.push (omit defaults/blanks). */
export function buildDetectionsParams(opts: {
  filter: string;
  q: string;
  id?: string;
}): URLSearchParams {
  const sp = new URLSearchParams();
  if (opts.filter && opts.filter !== 'all') sp.set('filter', opts.filter);
  const q = opts.q.trim();
  if (q) sp.set('q', q);
  if (opts.id) sp.set('id', opts.id);
  return sp;
}
