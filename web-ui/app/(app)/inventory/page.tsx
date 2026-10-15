import { PageHead, resolveInventorySelection } from '@akasecurity/dashboard-ui';
import type { HarnessEventsResponse } from '@akasecurity/schema';

import { db } from '../../lib/db';
import { renderLocale } from '../../lib/render-locale';
import { renderInstant } from '../../lib/rendered-at';
import { type InventorySearchParams, parseSelection } from './filters';
import { InventoryClient } from './InventoryClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Inventory' };

// The local model has no enforcement-event source yet, so a harness's "recent
// blocks" list is a fixed empty constant (no port method pretending to be a
// live query — see InventoryReadPort).
const EMPTY_HARNESS_EVENTS: HarnessEventsResponse = {
  counts: { block: 0, redact: 0, warn: 0 },
  items: [],
};

// Reads the local store's inventory (harnesses / assets / projects) for
// the left panel and the tables, resolves the selection the URL names, then
// reads the opened row's detail: an asset's detail, or a project's withheld
// files. Renders through the shared dashboard-ui views.
export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<InventorySearchParams>;
}) {
  const requested = parseSelection(await searchParams);

  // db() memoizes one store handle per process, so this per-request call is cheap.
  const inv = db().inventoryAssets;

  const [harnessesRes, assetsRes, projectsRes] = await Promise.all([
    inv.listHarnesses(),
    inv.listAssets({}),
    inv.listProjects(),
  ]);
  const harnesses = harnessesRes.items;
  const assetGroups = assetsRes.groups;
  const projects = projectsRes.items;

  const active = resolveInventorySelection(requested, { harnesses, projects, assetGroups });
  const item = active.item;

  const [assetDetail, blocked] = await Promise.all([
    item && item.type !== 'project' ? inv.getAsset(item.id) : Promise.resolve(null),
    item?.type === 'project'
      ? inv.getProjectTree(item.id, { filter: 'blocked' })
      : Promise.resolve(null),
  ]);

  return (
    <div className="flex h-full min-h-0 flex-col p-6">
      <PageHead
        title="Inventory"
        sub="Projects, skills, MCP servers, hooks & configuration — with attention flags & per-file LLM access"
      />
      <InventoryClient
        harnesses={harnesses}
        assetGroups={assetGroups}
        projects={projects}
        active={active}
        assetDetail={assetDetail}
        blocked={blocked?.files ?? []}
        harnessEvents={EMPTY_HARNESS_EVENTS}
        renderedAt={renderInstant()}
        locale={await renderLocale()}
      />
    </div>
  );
}
