'use server';

import { loadFindingContext } from '@akasecurity/local-ops';
import {
  type FindingContext,
  FindingContextQuery,
  ListFindingInstancesQuery,
  type ListFindingInstancesResponse,
  ListFindingLocationsQuery,
  type ListFindingLocationsResponse,
  ListFindingTypesQuery,
  type ListFindingTypesResponse,
} from '@akasecurity/schema';

import { db } from '../../lib/db';

// Data-returning Server Actions for the findings page's paginated lists: the
// type list and the location list on the left of their respective views, and
// the selected row's findings on the right of either.
//
// These are READS, so neither revalidates: appending a page must not re-render
// the rest of the route, which would discard the pages already accumulated in
// client state and reset the reader's scroll. The precedent for a data-returning
// action over a route handler is the scan page's listDirectory — this repo has
// no HTTP layer, and the network primitives a route handler would imply are
// ESLint-banned.
//
// Each parses its argument at the boundary: an action is a POST endpoint the
// browser can reach with anything, so a hand-rolled body must not reach the
// store as a query.

export async function loadMoreFindingTypes(raw: unknown): Promise<ListFindingTypesResponse> {
  const query = ListFindingTypesQuery.parse(raw);
  return db().findings.listFindingTypes(query);
}

export async function loadMoreFindingInstances(
  raw: unknown,
): Promise<ListFindingInstancesResponse> {
  const query = ListFindingInstancesQuery.parse(raw);
  return db().findings.listFindingInstances(query);
}

export async function loadMoreFindingLocations(
  raw: unknown,
): Promise<ListFindingLocationsResponse> {
  const query = ListFindingLocationsQuery.parse(raw);
  return db().findings.listFindingLocations(query);
}

// The open finding's masked excerpt, fetched once the drawer opens rather than
// carried on every list row (see SqliteFindingsRepository.findingContextSource).
// A failed read answers null — the drawer then says the code was not kept —
// rather than rejecting, so a store fault never becomes a framework error page.
export async function loadFindingContextAction(raw: unknown): Promise<FindingContext | null> {
  const parsed = FindingContextQuery.safeParse(raw);
  if (!parsed.success) return null;
  try {
    return await Promise.resolve(loadFindingContext(db().findings, parsed.data.id));
  } catch {
    return null;
  }
}
