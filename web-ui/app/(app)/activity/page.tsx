import {
  ActivitySummaryStripView,
  ActivityTokenUsageView,
  PageHead,
  rangeToFromIso,
  type SummaryStatItem,
  TIME_RANGES,
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
import { ActivityClient } from './ActivityClient';
import {
  type ActivitySearchParams,
  parseActivityRange,
  parseHarness,
  parseQuery,
  parseSelectedId,
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

  const activity = db().activity;

  // The time-range lower bound the session list uses, reused to scope the token
  // panel and the harness filter to the window on screen (range maps to `now − N
  // days`; rows/leaves/harnesses before it are excluded).
  const rangeFromMs = Date.parse(rangeToFromIso(range));

  const [stats, list, tokenReports, harnessOptions] = await Promise.all([
    activity.stats(),
    activity.listSessions(toListQuery(q, harness, range)),
    activity.tokenReports(rangeFromMs),
    // Only the harnesses that actually have sessions in this range populate the
    // filter (not the full enum).
    activity.harnessFacets(rangeFromMs),
  ]);
  const tokenUsage = aggregateTokenUsage(tokenReports);
  const rangeLabel = TIME_RANGES.find((r) => r.value === range)?.label;

  // Honor the pinned ?id when it's still in the filtered list; otherwise default
  // to the first row so the detail pane is never empty when sessions exist.
  const selectedId =
    requestedId && list.items.some((s) => s.id === requestedId)
      ? requestedId
      : (list.items[0]?.id ?? '');
  const [detail, sessionTokenReport] = selectedId
    ? await Promise.all([
        activity.getSession(selectedId),
        activity.tokenReportForSession(selectedId),
      ])
    : [null, null];

  const items: SummaryStatItem[] = [
    {
      icon: TerminalIcon,
      value: stats.sessionsToday,
      label: 'Sessions today',
      text: 'text-text-2',
      fill: 'bg-surface-2',
    },
    {
      icon: BoltIcon,
      value: stats.liveNow,
      label: 'Live now',
      text: 'text-ok',
      fill: 'bg-ok-fill',
    },
    {
      icon: ListIcon,
      value: stats.toolCallsToday.toLocaleString(),
      label: 'Tool calls',
      text: 'text-text-2',
      fill: 'bg-surface-2',
    },
    {
      icon: ShieldCheckIcon,
      value: stats.findingsToday,
      label: 'Findings triggered',
      text: 'text-sev-critical',
      fill: 'bg-sev-critical-fill',
    },
    {
      icon: ExternalShareIcon,
      value: stats.egressToday,
      label: 'Egress events',
      text: 'text-teal',
      fill: 'bg-teal-fill',
    },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHead
        title="Activity"
        sub="Your local harness sessions, reconstructed from the audit log"
        actions={<RangeSelect value={range} />}
      />

      <ActivitySummaryStripView items={items} isLoading={false} error={null} />

      <ActivityTokenUsageView
        summary={tokenUsage}
        isLoading={false}
        error={null}
        {...(rangeLabel ? { rangeLabel } : {})}
      />

      <ActivityClient
        sessions={list.items}
        detail={detail}
        tokenReport={sessionTokenReport}
        q={q}
        harness={harness}
        harnessOptions={harnessOptions}
        range={range}
        selectedId={selectedId}
        hasMore={Boolean(list.nextCursor)}
      />
    </div>
  );
}
