import { db } from '../../lib/db';
import {
  type FindingsSearchParams,
  parseFindingsFilters,
  parseQuery,
  parseSelectedFinding,
  parseSession,
  toGroupedQuery,
} from './filters';
import { FindingsClient } from './FindingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Findings' };

// Reads the local store's grouped findings for the URL's filters, then hands off
// to the client shell for the interactive table + detail sheet. Filters live in
// the URL so this re-runs (server-side) on every filter/search change. The
// Activity page deep-links here with ?session=… (scopes the list) and
// ?finding=… (opens the detail sheet on that group/instance).
export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<FindingsSearchParams>;
}) {
  const sp = await searchParams;
  const filters = parseFindingsFilters(sp);
  const query = parseQuery(sp);
  const session = parseSession(sp);
  const selectedId = parseSelectedFinding(sp);

  const data = await db().findings.listGroupedFindings(toGroupedQuery(filters, query, session));
  // The store returns totals over the full filtered set but caps `items`, so the
  // table's "showing first N" hint fires when more groups match than are shown.
  const hasMore = data.totals.groups > data.items.length;

  return (
    <FindingsClient
      data={data}
      filters={filters}
      query={query}
      session={session}
      selectedId={selectedId}
      hasMore={hasMore}
    />
  );
}
