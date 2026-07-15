import { PageHead, resolveInventorySelection } from '@akasecurity/dashboard-ui';
import type { HarnessEventsResponse } from '@akasecurity/schema';

import { db } from '../../lib/db';
import {
  type InventorySearchParams,
  parseDrawer,
  parseFileQuery,
  parsePath,
  parseSelection,
} from './filters';
import { InventoryClient } from './InventoryClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Inventory' };

// The local model has no enforcement-event source yet, so the HarnessOverview
// "recent blocks" list is a fixed empty constant (no port method pretending to be
// a live query — see InventoryReadPort). Populate when a real scanner lands.
const EMPTY_HARNESS_EVENTS: HarnessEventsResponse = {
  counts: { block: 0, redact: 0, warn: 0 },
  items: [],
};

// Reads the local store's asset inventory (harnesses / assets / projects / stats)
// for the nav, resolves the active selection from the URL (defaulting to the first
// available node), then reads that node's detail (project file tree + blocked
// strip / harness overview / asset detail / file drawer). Selection + file-browser
// state live in the URL so this re-runs server-side on every change. Renders
// through the shared dashboard-ui views, reading local persistence directly —
// the store is server-only.
export default async function InventoryPage({
  searchParams,
}: {
  searchParams: Promise<InventorySearchParams>;
}) {
  const sp = await searchParams;
  const requested = parseSelection(sp);
  const path = parsePath(sp);
  const fq = parseFileQuery(sp);
  const drawer = parseDrawer(sp);

  // db() memoizes one store handle per process, so this per-request call is cheap.
  const inv = db().inventoryAssets;

  const [harnessesRes, assetsRes, projectsRes, stats] = await Promise.all([
    inv.listHarnesses(),
    inv.listAssets({}),
    inv.listProjects(),
    inv.getInventoryStats(),
  ]);
  const harnesses = harnessesRes.items;
  const assetGroups = assetsRes.groups;
  const projects = projectsRes.items;

  // Resolve the active selection via the shared dashboard-ui resolver.
  const activeSel = resolveInventorySelection(requested, { harnesses, projects, assetGroups });

  // Right-pane targets + their detail, derived from the active selection.
  const proj =
    activeSel?.type === 'project' ? (projects.find((p) => p.id === activeSel.id) ?? null) : null;
  const selHarness =
    activeSel?.type === 'harness' ? (harnesses.find((h) => h.id === activeSel.id) ?? null) : null;
  const selAssetId =
    activeSel && activeSel.type !== 'project' && activeSel.type !== 'harness' ? activeSel.id : null;

  const searching = fq.trim().length > 0;
  const [tree, blocked, assetDetail, fileDetail] = await Promise.all([
    proj ? inv.getProjectTree(proj.id, { path: path.join('/'), q: fq }) : Promise.resolve(null),
    proj && !searching ? inv.getProjectTree(proj.id, { filter: 'blocked' }) : Promise.resolve(null),
    selAssetId ? inv.getAsset(selAssetId) : Promise.resolve(null),
    proj && drawer ? inv.getProjectFile(proj.id, drawer) : Promise.resolve(null),
  ]);
  const harnessEvents = selHarness ? EMPTY_HARNESS_EVENTS : null;

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHead
        title="Inventory"
        sub="Projects, skills, MCP servers, hooks & configuration — with attention flags & per-file LLM access"
      />
      <InventoryClient
        harnesses={harnesses}
        assetGroups={assetGroups}
        projects={projects}
        attention={stats.attention}
        activeSel={activeSel}
        proj={proj}
        selHarness={selHarness}
        assetDetail={assetDetail}
        tree={tree}
        blocked={blocked?.files ?? []}
        harnessEvents={harnessEvents}
        fileDetail={fileDetail}
        path={path}
        fq={fq}
        drawer={drawer}
      />
    </div>
  );
}
