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
  WebCaptureCardView,
  type WebCaptureSiteRow,
} from '@akasecurity/dashboard-ui';
import { WEB_CAPTURE_DRIFT_RULE, webCaptureReport } from '@akasecurity/detections';
import { readEffectiveSettings } from '@akasecurity/persistence';
import { isWebChatCaptureConsentValid, webChatCaptureOf } from '@akasecurity/schema';

import { RangeSelect } from '../../components/RangeSelect';
import { db } from '../../lib/db';
import { renderInstant } from '../../lib/rendered-at';
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

/**
 * The DRIFTING web-chat capture sites, as the card renders them — empty
 * whenever there is nothing to act on, which is when the card is not rendered
 * at all.
 *
 * Two gates, and each answers a different way of being wrong:
 *
 *  - CONSENT, the same one `aka extension status` applies. A machine whose
 *    web-chat capture consent has been revoked — or invalidated wholesale by a
 *    consent-version bump, since a grant recorded against an older version
 *    reads as revoked — records no further status, so the newest row it holds
 *    can never be superseded by a later one. Rendering that row anyway tells
 *    the user to reload a tab nothing is watching. Reading consent here rather
 *    than inferring it from the rows keeps one definition of "capture is on"
 *    across the CLI, the plugin screens and this page.
 *
 *  - DRIFT. This card is a finding surface, not an inventory. Every site is in
 *    `webCaptureReport`'s output including one nothing has reported for, and on
 *    a build that declares no endpoints they all derive to `standby` or
 *    `unreported` — so an ungated card is a permanent fixture asking for an
 *    action whose only available outcome is the other neutral word. A card
 *    that is always present is one people stop reading before the day it says
 *    something.
 *
 * `now` is the route's own render instant, so the read's recency window is
 * measured against the same instant every other age on the page is.
 */
function webCaptureDriftRows(now: number): WebCaptureSiteRow[] {
  const webChat = webChatCaptureOf(readEffectiveSettings().settings);
  if (!isWebChatCaptureConsentValid(webChat.consent)) return [];
  return webCaptureReport(db().captureStatus.latest(now))
    .filter((s) => s.drift)
    .map((s) => ({
      tool: s.tool,
      stateLabel: s.state,
      headline: s.headline,
      ...(s.remediation !== undefined ? { remediation: s.remediation } : {}),
      drift: s.drift,
    }));
}

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

  // One instant for the whole route. The feed below is a SERVER component, so
  // there is no hydration render here to disagree with — the instant is required
  // because the view has no clock of its own to fall back on, which is what keeps
  // it honest if it ever gains a `use client` directive.
  const renderedAt = renderInstant();

  // Synchronous — not part of the Promise.all above.
  const captureSites = webCaptureDriftRows(renderedAt);
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
        <RecentlyResolvedCardView
          items={recentlyResolved.items}
          isLoading={false}
          error={null}
          renderedAt={renderedAt}
        />
      </div>

      {captureSites.length > 0 && (
        <div className="mt-4 xl:mt-5">
          <WebCaptureCardView
            sites={captureSites}
            ruleId={WEB_CAPTURE_DRIFT_RULE.ruleId}
            severity={WEB_CAPTURE_DRIFT_RULE.severity}
            isLoading={false}
            error={null}
          />
        </div>
      )}
    </div>
  );
}
