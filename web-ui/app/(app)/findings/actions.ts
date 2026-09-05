'use server';

import {
  ListFindingInstancesQuery,
  type ListFindingInstancesResponse,
  ListFindingTypesQuery,
  type ListFindingTypesResponse,
} from '@akasecurity/schema';

import { db } from '../../lib/db';

// Data-returning Server Actions for the findings page's two paginated lists:
// the type list on the left, and the selected type's findings on the right.
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
