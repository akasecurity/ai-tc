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
    // Searching narrows the register, not the review queue, so skip the
    // needs-review scan (and its RSC payload) entirely while a term is set.
    // The empty list is what hides the strip and empties the sheet.
    q ? Promise.resolve({ items: [] }) : shares.needsReview(),
  ]);
  const destination = dest ? await shares.getDestination(dest) : null;

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHead
        title="Data Shares"
        sub="Outbound data egress detected in your software — grouped by destination"
        actions={
          <span className="text-ui text-text-3">
            <b className="text-text">{stats.destinations}</b> destinations ·{' '}
            <b className="text-text">{stats.endpoints}</b> endpoints ·{' '}
            <b className="text-text">{stats.callSites}</b> call sites
          </span>
        }
      />

      <DataSharesClient
        q={q}
        groups={list.groups}
        review={review.items}
        destination={destination}
        selectedDest={dest}
        selectedEndpoint={ep}
      />
    </div>
  );
}
