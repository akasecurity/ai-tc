import { EMPTY_FILTERS } from '@akasecurity/dashboard-ui';
import type { EnforcementActionKind, Severity, TimeRange } from '@akasecurity/schema';

import { buildFindingsParams } from '../findings/filters';

// Deep links from the Security widgets into the findings list.
//
// Two rules hold every link here together, and both are about the destination
// AGREEING with the number that was clicked:
//
//  1. Every link targets `view=flat`. It is the only view whose query
//     (`toInstancesQuery`) honours every filter dimension, so the list that opens
//     is the set the widget counted. Under `grouped` the left panel ignores the
//     finding-level dimensions, so the same URL would show a different total.
//  2. `range` is carried exactly where the widget's own store read is
//     range-scoped, and omitted where it is not. On `/findings` an ABSENT range
//     means all time — it is not defaulted the way `/security` defaults to 7d —
//     so omitting it is what makes an all-time widget agree, and carrying it is
//     what makes a windowed one agree.
//
// Nothing is assembled by hand: each builder goes through `buildFindingsParams`,
// which already drops any param the target view would ignore (`repo`/`file`
// outside `flat`, `type` under `grouped`). Building a query string here instead
// would be a second spelling of that grammar, free to drift from the page that
// reads it — and a dropped param is invisible, surviving into a shared link as a
// filter that silently stopped working.

/** `/findings` with the given params, or bare when there are none. */
function findingsHref(sp: URLSearchParams): string {
  const qs = sp.toString();
  return qs ? `/findings?${qs}` : '/findings';
}

/**
 * Findings enforced with one action, in the widget's window.
 *
 * `EnforcementActionKind` and the URL's `action` vocabulary are the same three
 * strings, and the store's `ACTION_TO_KIND` is the exact inverse of the findings
 * layer's `toDbAction`, so this needs no translation.
 */
export function enforcementHref(kind: EnforcementActionKind, range: TimeRange): string {
  return findingsHref(
    buildFindingsParams({ ...EMPTY_FILTERS, action: [kind] }, '', '', { view: 'flat', range }),
  );
}

/**
 * Every finding of one severity.
 *
 * Deliberately carries NO range: `severitySummary()` is whole-store, so a windowed
 * destination would show fewer findings than the number the user clicked.
 */
export function severityHref(severity: Severity): string {
  return findingsHref(
    buildFindingsParams({ ...EMPTY_FILTERS, severity: [severity] }, '', '', { view: 'flat' }),
  );
}

/**
 * Findings from one repository, in the widget's window.
 *
 * `repo` is an exact match on the same `audit_events.repo` the widget groups by,
 * and `buildFindingsParams` writes it only under `view=flat` — which is why the
 * view is set rather than left to default.
 */
export function topSourceHref(repo: string, range: TimeRange): string {
  return findingsHref(buildFindingsParams(EMPTY_FILTERS, '', '', { view: 'flat', range, repo }));
}

/**
 * The resolved findings of one rule, narrowed to the file the row names.
 *
 * A superset of the row by construction: the feed additionally requires that the
 * finding was resolved by fixing it at source, and no findings filter expresses a
 * resolution method. The row carries no count, so nothing is contradicted.
 *
 * Narrowed by REPO as well as file: `?file=` is an exact match on a path stored
 * relative to its repository, so `.env` on its own selects that file in every repo
 * the machine has scanned — findings the row did not name.
 *
 * An empty repo or path yields no param at all — `buildFindingsParams` writes each
 * key only for a non-empty value, which is the behaviour the suite pins here rather
 * than re-guarding: an exact match on `''` would select nothing instead of
 * declining to narrow.
 */
export function resolvedFindingHref(ruleId: string, repo: string, path: string): string {
  return findingsHref(
    buildFindingsParams({ ...EMPTY_FILTERS, type: [ruleId], status: ['resolved'] }, '', '', {
      view: 'flat',
      repo,
      file: path,
    }),
  );
}

/**
 * The findings of one detection rule, in the widget's window.
 *
 * Filters by RULE rather than by the recommendation's category because the card
 * counts per rule (see `bucketize`) — the label and the destination therefore
 * describe the same set. `severity` is never added alongside: it is constant
 * within a rule, so it would filter every row or none.
 */
export function recommendationHref(ruleId: string, range: TimeRange): string {
  return findingsHref(
    buildFindingsParams({ ...EMPTY_FILTERS, type: [ruleId] }, '', '', { view: 'flat', range }),
  );
}

/** The unfiltered findings list for the card's own window. */
export function allFindingsHref(range: TimeRange): string {
  return findingsHref(buildFindingsParams(EMPTY_FILTERS, '', '', { view: 'flat', range }));
}
