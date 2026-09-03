import {
  ActivityTokenUsageView,
  PageHead,
  rangeLabel,
  rangeToFromIso,
  type SummaryStatItem,
  SummaryStripView,
} from '@akasecurity/dashboard-ui';
import { aggregateTokenUsage } from '@akasecurity/schema';

import {
  BoltIcon,
  ExternalShareIcon,
  ListIcon,
  ShieldCheckIcon,
  TerminalIcon,
} from '../../components/icons';
import { RangeSelect } from '../../components/RangeSelect';
import { db } from '../../lib/db';
import { renderInstant } from '../../lib/rendered-at';
import { ActivityClient } from './ActivityClient';
import {
  type ActivitySearchParams,
  parseActivityRange,
  parseExpanded,
  parseHarness,
  parseQuery,
  parseSelectedId,
  parseShowEmpty,
  toListQuery,
} from './filters';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Activity' };

// Reads the local store's reconstructed harness sessions — today stats + the
// filtered session list — for the URL's search/harness/range, resolves the
// selected session detail, then hands off to the client shell for the interactive
// master/detail. List state lives in the URL so this re-runs server-side on every
// change. Renders through the shared dashboard-ui views, reading local
// persistence directly — the store is server-only.
export default async function ActivityPage({
  searchParams,
}: {
  searchParams: Promise<ActivitySearchParams>;
}) {
  const sp = await searchParams;
  const q = parseQuery(sp);
  const harness = parseHarness(sp);
  const range = parseActivityRange(sp);
  const requestedId = parseSelectedId(sp);
  const showEmpty = parseShowEmpty(sp);
  const expanded = parseExpanded(sp);

  const activity = db().activity;

  // Captured before the range bound below so the query window and every
  // rendered label this request produces come from the SAME instant, rather
  // than a range bound computed a clock read apart from the labels it scopes.
  const renderedAt = renderInstant();

  // The time-range lower bound the session list uses, reused to scope the token
  // panel and the harness filter to the window on screen (range maps to `now − N
  // days`; rows/leaves/harnesses before it are excluded).
  const rangeFromMs = Date.parse(rangeToFromIso(range, renderedAt));

  const [stats, list, tokenReports, harnessOptions] = await Promise.all([
    activity.stats(),
    activity.listSessions(toListQuery(q, harness, range, showEmpty, renderedAt)),
    activity.tokenReports(rangeFromMs),
    // Only the harnesses that actually have sessions in this range populate the
    // filter (not the full enum).
    activity.harnessFacets(rangeFromMs),
  ]);
  const tokenUsage = aggregateTokenUsage(tokenReports);
  const label = rangeLabel(range);

  // Honor the pinned ?id whenever one is present — a deep link (e.g. the
  // findings drawer's "View session") must show THAT session even when the
  // current search/range excludes it from the list; an unknown id renders the
  // detail pane's empty state rather than silently swapping in another session.
  // With no ?id, default to the first row so the pane isn't empty needlessly.
  const selectedId = requestedId || (list.items[0]?.id ?? '');
  const [detail, sessionTokenReport] = selectedId
    ? await Promise.all([
        activity.getSession(selectedId),
        activity.tokenReportForSession(selectedId),
      ])
    : [null, null];

  // The session → findings drilldown. Two numbers coexist: `detail.findings`
  // tallies transcript firings (every re-detection counts), while /findings
  // lists the live-enforced store's unique values — so the link carries its
  // destination's own count and appears only when that page has rows to show.
  const liveCount = detail ? await db().findings.sessionFindingsCount(detail.id) : 0;
  const liveFindings =
    detail && liveCount > 0
      ? { count: liveCount, href: `/findings?session=${encodeURIComponent(detail.id)}` }
      : null;

  const items: SummaryStatItem[] = [
    {
      icon: TerminalIcon,
      value: stats.sessionsToday.toLocaleString(),
      label: 'Sessions today',
      tone: 'neutral',
    },
    {
      icon: BoltIcon,
      value: stats.liveNow.toLocaleString(),
      label: 'Live now',
      tone: 'ok',
    },
    {
      icon: ListIcon,
      value: stats.toolCallsToday.toLocaleString(),
      label: 'Tool calls',
      tone: 'neutral',
    },
    {
      icon: ShieldCheckIcon,
      value: stats.findingsToday.toLocaleString(),
      label: 'Findings triggered',
      tone: 'critical',
    },
    {
      icon: ExternalShareIcon,
      value: stats.egressToday.toLocaleString(),
      label: 'Egress events',
      tone: 'teal',
    },
  ];
  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      {/* Token usage sits in the filter bar beside the range picker rather than
          in a card of its own: it is a per-range summary like the range itself,
          and the vertical band it used to occupy is the session list's. */}
      <PageHead
        title="Activity"
        sub="Your local harness sessions, reconstructed from the audit log"
        actions={
          <>
            <ActivityTokenUsageView
              summary={tokenUsage}
              isLoading={false}
              error={null}
              rangeLabel={label}
            />
            <RangeSelect value={range} />
          </>
        }
      />

      <SummaryStripView items={items} isLoading={false} />

      <ActivityClient
        sessions={list.items}
        detail={detail}
        tokenReport={sessionTokenReport}
        liveFindings={liveFindings}
        q={q}
        harness={harness}
        harnessOptions={harnessOptions}
        range={range}
        selectedId={selectedId}
        hasMore={Boolean(list.nextCursor)}
        emptyCount={list.emptyCount}
        showEmpty={showEmpty}
        expanded={expanded}
        renderedAt={renderedAt}
      />
    </div>
  );
}
