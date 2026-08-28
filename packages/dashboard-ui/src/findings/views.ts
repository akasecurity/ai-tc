/**
 * The findings view vocabulary, and nothing else.
 *
 * Its own module because it is the one part of findings/meta.ts that a ROUTER
 * needs. A route's `validateSearch` runs at route-tree construction, so whatever
 * it reaches is eager by nature — and meta.ts imports a ui-kit tone and the icon
 * set, while the package barrel above it re-exports the d3-shape charts. Three
 * constants were enough to put a chart library on the critical path of a page
 * that renders none.
 *
 * This file must stay import-free. That is the whole property: anything it
 * reaches, a router reaches too.
 */

/** The findings list's grouping modes, in display order. */
export const FINDINGS_VIEWS = ['grouped', 'flat', 'files'] as const;

export type FindingsView = (typeof FINDINGS_VIEWS)[number];

/** The default view — what an absent `?view=` means. */
export const DEFAULT_FINDINGS_VIEW: FindingsView = 'grouped';

export function isFindingsView(value: string): value is FindingsView {
  return (FINDINGS_VIEWS as readonly string[]).includes(value);
}
