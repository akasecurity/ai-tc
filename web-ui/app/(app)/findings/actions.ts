'use server';

import {
  ListFindingInstancesQuery,
  type ListFindingInstancesResponse,
  ListGroupedFindingsQuery,
  type ListGroupedFindingsResponse,
} from '@akasecurity/schema';

import { db } from '../../lib/db';

// Data-returning Server Actions for the findings list's "Load more".
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

export async function loadMoreGroupedFindings(raw: unknown): Promise<ListGroupedFindingsResponse> {
  const query = ListGroupedFindingsQuery.parse(raw);
  return db().findings.listGroupedFindings(query);
}

export async function loadMoreFindingInstances(
  raw: unknown,
): Promise<ListFindingInstancesResponse> {
  const query = ListFindingInstancesQuery.parse(raw);
  return db().findings.listFindingInstances(query);
}
