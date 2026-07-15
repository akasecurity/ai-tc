import { PageHead, StatTile } from '@akasecurity/dashboard-ui';

import { ActivityIcon, BracesIcon, ListIcon, ShieldCheckIcon } from '../../components/icons';
import { db } from '../../lib/db';
import { DetectionsClient } from './DetectionsClient';
import {
  type DetectionsSearchParams,
  parseDetectionFilter,
  parseDetectionQuery,
  parseSelectedId,
  toListQuery,
} from './filters';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Detections' };

// Reads the local store's installed detections + stats for the URL's filter/search,
// resolves the selected detail, then hands off to the client shell for the
// interactive master/detail + rule inspector. List state lives in the URL so this
// re-runs (server-side) on every filter/search/select change.
export default async function DetectionsPage({
  searchParams,
}: {
  searchParams: Promise<DetectionsSearchParams>;
}) {
  const sp = await searchParams;
  const filter = parseDetectionFilter(sp);
  const query = parseDetectionQuery(sp);
  const requestedId = parseSelectedId(sp);

  const detections = db().detections;
  const [stats, list] = await Promise.all([
    detections.getDetectionStats(),
    detections.listDetections(toListQuery(filter, query)),
  ]);

  // Honor the pinned ?id when it's still in the filtered list; otherwise default
  // to the first row so the detail pane is never empty when detections exist.
  const selectedId =
    requestedId && list.items.some((d) => d.id === requestedId)
      ? requestedId
      : (list.items[0]?.id ?? '');
  const detail = selectedId ? await detections.getDetectionDetail(selectedId) : null;

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHead title="Detections" sub="Rules that generate findings from code, prompts & pastes" />

      {/* stat strip */}
      <div className="grid grid-cols-4 gap-4">
        <StatTile
          icon={ListIcon}
          iconBg="var(--color-primary-tint)"
          iconColor="var(--color-primary)"
          label="Detections"
          value={String(stats.detections)}
        />
        <StatTile
          icon={BracesIcon}
          iconBg="var(--color-violet-fill)"
          iconColor="var(--color-violet)"
          label="Rules"
          value={String(stats.rules)}
        />
        <StatTile
          icon={ShieldCheckIcon}
          iconBg="var(--color-ok-fill)"
          iconColor="var(--color-ok)"
          label="Active"
          value={`${String(stats.active)} / ${String(stats.detections)}`}
        />
        <StatTile
          icon={ActivityIcon}
          iconBg="var(--color-surface-2)"
          iconColor="var(--color-text-2)"
          label="Findings · 30d"
          value={stats.findingsLast30d.toLocaleString()}
        />
      </div>

      <DetectionsClient
        list={list}
        detail={detail}
        filter={filter}
        query={query}
        selectedId={selectedId}
      />
    </div>
  );
}
