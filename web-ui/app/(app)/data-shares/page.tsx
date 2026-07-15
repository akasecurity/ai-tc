import { PageHead } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { DataSharesClient } from './DataSharesClient';
import { type DataSharesSearchParams, parseQuery, parseSelection } from './filters';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Data Shares' };

// Reads the local store's outbound-egress register (stats + grouped destinations +
// the needs-review strip) for the URL's search term, resolves the selected
// destination detail, then hands off to the client shell for the interactive
// table + detail drawer. Search/selection live in the URL so this re-runs
// server-side on every change. Renders through the shared dashboard-ui views,
// reading local persistence directly — the store is server-only.
export default async function DataSharesPage({
  searchParams,
}: {
  searchParams: Promise<DataSharesSearchParams>;
}) {
  const sp = await searchParams;
  const q = parseQuery(sp);
  const { dest, ep } = parseSelection(sp);

  const shares = db().shares;

  const [stats, list, review] = await Promise.all([
    shares.stats(),
    shares.listDestinations({ q, groupBy: 'destination', review: false }),
    // The client only renders the review strip when the search box is empty, so
    // skip the destination+endpoint scan (and its RSC payload) while searching.
    q ? Promise.resolve({ items: [] }) : shares.needsReview(),
  ]);
  const destination = dest ? await shares.getDestination(dest) : null;

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHead
        title="Data Shares"
        sub="Outbound data egress detected in your software — grouped by destination"
      />

      <DataSharesClient
        q={q}
        stats={stats}
        groups={list.groups}
        review={review.items}
        destination={destination}
        selectedDest={dest}
        selectedEndpoint={ep}
      />
    </div>
  );
}
