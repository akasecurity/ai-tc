import {
  buildRecommendedActions,
  EnforcementCardView,
  type FindingsChartPoint,
  FindingsOverTimeCardView,
  type MttrChartPoint,
  MttrTrendCardView,
  PageHead,
  parseTimeRange,
  rangeLabel,
  RecentlyResolvedCardView,
  ScanCoverageCardView,
  SeverityCardView,
  TopSourcesCardView,
} from '@akasecurity/dashboard-ui';

import { RangeSelect } from '../../components/RangeSelect';
import { db } from '../../lib/db';
import { RecommendedActionsCard } from './RecommendedActionsCard';

// node:sqlite (via @akasecurity/persistence) runs only on the Node.js runtime.
export const runtime = 'nodejs';
// Reads the local store on every request — never statically prerendered.
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Security' };

// Resolve the ISO date bucket to a short axis label, exactly as the dashboard's
// useFindingsTimeseries hook does (UTC so the label matches the bucket).
const bucketLabel = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  timeZone: 'UTC',
});

export default async function SecurityPage({
  searchParams,
}: {
  searchParams: Promise<{ range?: string }>;
}) {
  const range = parseTimeRange((await searchParams).range);
  const label = rangeLabel(range);
  const security = db().security;

  const [
    severity,
    enforcement,
    timeseries,
    mttrTrend,
    coverage,
    sources,
    recentlyResolved,
    recentFindings,
  ] = await Promise.all([
    security.severitySummary(),
    security.enforcementActions(range),
    security.findingsTimeseries(range),
    security.mttrTrend(range),
    security.scanCoverage(range),
    security.topSources(range, { limit: 5 }),
    security.recentlyResolved(),
    db().findings.recentFindings({ limit: 500 }),
  ]);

  // Same prioritization as the CLI TUI's Recommend screen — pure, computed
  // server-side over the recent findings.
  const recommendations = buildRecommendedActions(recentFindings);

  const points: FindingsChartPoint[] = timeseries.points.map((p) => ({
    ...p,
    label: bucketLabel.format(new Date(p.timestamp)),
  }));

  const mttrPoints: MttrChartPoint[] = mttrTrend.points.map((p) => ({
    ...p.bySeverity,
    label: bucketLabel.format(new Date(p.timestamp)),
  }));

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Security"
        sub="Data-exposure posture across all AI traffic"
        actions={<RangeSelect value={range} />}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_1fr_1.25fr] xl:gap-5">
        <EnforcementCardView {...enforcement} isLoading={false} error={null} rangeLabel={label} />
        <SeverityCardView {...severity} isLoading={false} error={null} />
        <ScanCoverageCardView {...coverage} isLoading={false} error={null} rangeLabel={label} />
      </div>

      <FindingsOverTimeCardView points={points} isLoading={false} error={null} />

      <MttrTrendCardView points={mttrPoints} isLoading={false} error={null} />

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1.55fr_1fr] xl:mt-5 xl:gap-5">
        <RecommendedActionsCard items={recommendations} />
        <TopSourcesCardView {...sources} isLoading={false} error={null} />
      </div>

      <div className="mt-4 xl:mt-5">
        <RecentlyResolvedCardView items={recentlyResolved.items} isLoading={false} error={null} />
      </div>
    </div>
  );
}
