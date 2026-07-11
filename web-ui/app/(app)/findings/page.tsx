import { db } from '../../lib/db';
import {
  type FindingsSearchParams,
  parseFindingsFilters,
  parseQuery,
  toGroupedQuery,
} from './filters';
import { FindingsClient } from './FindingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Reads the local store's grouped findings for the URL's filters, then hands off
// to the client shell for the interactive table + detail sheet. Filters live in
// the URL so this re-runs (server-side) on every filter/search change.
export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<FindingsSearchParams>;
}) {
  const sp = await searchParams;
  const filters = parseFindingsFilters(sp);
  const query = parseQuery(sp);

  const data = await db().findings.listGroupedFindings(toGroupedQuery(filters, query));
  // The store returns totals over the full filtered set but caps `items`, so the
  // table's "showing first N" hint fires when more groups match than are shown.
  const hasMore = data.totals.groups > data.items.length;

  return <FindingsClient data={data} filters={filters} query={query} hasMore={hasMore} />;
}
