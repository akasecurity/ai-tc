import { PageHead, PolicyStatsView } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { PoliciesClient } from './PoliciesClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Policies' };

// Reads the local store's built-in policy catalog (stats + list + the selected
// detail) and hands off to the client shell for the interactive master/detail.
// Selection lives in the URL (?id) so this Server Component re-queries the detail
// on every change — the OSS store is server-only. Renders through the shared
// dashboard-ui views, reading local persistence directly.
export default async function PoliciesPage({
  searchParams,
}: {
  searchParams: Promise<{ id?: string }>;
}) {
  const requestedId = (await searchParams).id;

  const local = db();
  const catalog = local.policyCatalog;
  const [stats, list] = await Promise.all([catalog.getPolicyStats(), catalog.getPolicyList()]);

  // Honor the pinned ?id when it's still in the catalog; otherwise default to the
  // first policy so the detail pane is never empty when policies exist.
  const selectedId =
    requestedId && list.items.some((p) => p.id === requestedId)
      ? requestedId
      : (list.items[0]?.id ?? '');
  const detail = selectedId ? await catalog.getPolicyDetail(selectedId) : null;

  return (
    // Height-capped from `lg` up, which is where the master/detail below is two
    // columns: capped, the page never scrolls and each pane scrolls itself, the
    // way Detections/Activity/Inventory behave. Below `lg` the grid stacks into
    // one column, and capping there would split the viewport between two
    // letterboxed panes — so the floor (and the page scroll it implies) stays.
    <div className="flex min-h-full flex-col px-8 pb-8 pt-7 lg:h-full lg:min-h-0">
      <PageHead title="Policies" sub="Enforcement actions detections take when they match" />

      <PolicyStatsView stats={stats} className="mb-3" />

      <PoliciesClient items={list.items} detail={detail} selectedId={selectedId} />
    </div>
  );
}
