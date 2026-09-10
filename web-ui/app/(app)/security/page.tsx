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
import type { EnforcementActionKind, Severity } from '@akasecurity/schema';

import { RangeSelect } from '../../components/RangeSelect';
import { db } from '../../lib/db';
import { renderInstant } from '../../lib/rendered-at';
import {
  allFindingsHref,
  enforcementHref,
  recommendationHref,
  resolvedFindingHref,
  severityHref,
  topSourceHref,
} from './links';
import { RecommendedActionsCard } from './RecommendedActionsCard';
import { WidgetNavigation } from './WidgetNavigation';

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
    recommendationInputs,
  ] = await Promise.all([
    security.severitySummary(),
    security.enforcementActions(range),
    security.findingsTimeseries(range),
    security.mttrTrend(range),
    security.scanCoverage(range),
    security.topSources(range, { limit: 5 }),
    security.recentlyResolved(),
    security.recommendationInputs(range),
  ]);

  // Same prioritization as the CLI TUI's Recommend screen — pure, computed
  // server-side. Read over the SELECTED RANGE rather than a "newest N findings"
  // cap: the cap made "recent" mean a different span on every machine, and no URL
  // can express one, so the card's counts could never agree with the findings page
  // each row now links to.
  // The destination is built INSIDE the builder rather than patched over it
  // afterwards: the card ranks by category but counts by the rule it names, so the
  // link has to be that rule's, and a host that forgot to patch would ship a row
  // reading "<rule> · N findings" over the whole unfiltered list.
  const recommendations = buildRecommendedActions(recommendationInputs, {
    hrefForRule: (ruleId) => recommendationHref(ruleId, range),
  });

  const points: FindingsChartPoint[] = timeseries.points.map((p) => ({
    ...p,
    // `low` is optional on the wire (additive) and required by the chart, which
    // plots it as a series — resolve the absent case here rather than leaving the
    // chart to read a hole as a gap in the data.
    low: p.low ?? 0,
    label: bucketLabel.format(new Date(p.timestamp)),
  }));

  const mttrPoints: MttrChartPoint[] = mttrTrend.points.map((p) => ({
    ...p.bySeverity,
    label: bucketLabel.format(new Date(p.timestamp)),
  }));

  // One instant for the whole route. The feed below is a SERVER component, so
  // there is no hydration render here to disagree with — the instant is required
  // because the view has no clock of its own to fall back on, which is what keeps
  // it honest if it ever gains a `use client` directive.
  const renderedAt = renderInstant();

  // Deep links, built here rather than in the views so `@akasecurity/dashboard-ui`
  // takes no router dependency. A key is emitted only where a link can honour the
  // number beside it, so "don't link this" is spelled as an ABSENT key rather than
  // as a branch inside the view.
  //
  // Built with keyed loops rather than `Object.fromEntries`, which widens to
  // `{ [k: string]: string }` and therefore type-checks against these enum-keyed
  // props whatever the key is — the one boundary the enum spelling exists to guard.
  const actionHrefs: Partial<Record<EnforcementActionKind, string>> = {};
  // Gated on `count > 0` for the same reason as the severity loop below:
  // `enforcementActions` zero-fills all three kinds and the card renders every tile
  // whenever the total is non-zero, so an ungated map sends "Redacted 0" to an
  // empty list.
  for (const a of enforcement.actions) {
    if (a.count > 0) actionHrefs[a.kind] = enforcementHref(a.kind, range);
  }

  // A severity with no findings gets no link: `severitySummary` zero-fills all four,
  // so linking unconditionally would send "Medium 0" to a list holding nothing.
  const severityHrefs: Partial<Record<Severity, string>> = {};
  for (const s of severity.bySeverity) {
    if (s.count > 0) severityHrefs[s.severity] = severityHref(s.severity);
  }
  // Repos only: the findings page has no author dimension, so a `user` source has
  // no destination that could match its count. The local store derives no user
  // sources today, which is why the unlinked case is covered in the view's own suite.
  const sourceHrefs: Record<string, string> = {};
  for (const s of sources.items) {
    // A named repo is the only source a findings filter can express; an empty name
    // would drop the `repo` param and open the whole window unfiltered.
    if (s.kind === 'repo' && s.name) sourceHrefs[s.id] = topSourceHref(s.name, range);
  }
  const itemHrefs: Record<string, string> = {};
  for (const i of recentlyResolved.items) {
    itemHrefs[i.findingKey] = resolvedFindingHref(i.ruleId, i.repo ?? '', i.path);
  }

  return (
    <div className="p-6">
      <PageHead
        title="Security"
        sub="Data-exposure posture across all AI traffic"
        actions={<RangeSelect value={range} />}
      />

      <WidgetNavigation>
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_1fr_1.25fr] xl:gap-5">
          <EnforcementCardView
            {...enforcement}
            isLoading={false}
            error={null}
            rangeLabel={label}
            actionHrefs={actionHrefs}
          />
          <SeverityCardView
            {...severity}
            isLoading={false}
            error={null}
            severityHrefs={severityHrefs}
          />
          {/* Scan coverage is deliberately unlinked: its number is a curated
              capability constant, not a measurement of anything in the store, so no
              destination could corroborate it — and a supported provider with no
              findings would land on an empty list. */}
          <ScanCoverageCardView {...coverage} isLoading={false} error={null} rangeLabel={label} />
        </div>

        <FindingsOverTimeCardView points={points} isLoading={false} error={null} />

        <MttrTrendCardView points={mttrPoints} isLoading={false} error={null} />

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1.55fr_1fr] xl:mt-5 xl:gap-5">
          <RecommendedActionsCard
            items={recommendations}
            viewAllHref={allFindingsHref(range)}
            rangeLabel={label}
          />
          <TopSourcesCardView
            {...sources}
            isLoading={false}
            error={null}
            sourceHrefs={sourceHrefs}
          />
        </div>

        <div className="mt-4 xl:mt-5">
          <RecentlyResolvedCardView
            items={recentlyResolved.items}
            isLoading={false}
            error={null}
            renderedAt={renderedAt}
            itemHrefs={itemHrefs}
          />
        </div>
      </WidgetNavigation>
    </div>
  );
}
