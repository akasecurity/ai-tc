import type { FindingsTimeseriesPoint, TimeseriesGranularity } from '@akasecurity/schema';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  Skeleton,
} from '@akasecurity/ui-kit';

import { COLORS } from '../lib/colors.ts';
import { AreaChart } from '../shared/charts.tsx';
import { AnalyticsIcon } from '../shared/icons.tsx';
import { WidgetEmpty, WidgetError } from './widget-shared.tsx';

// One day's point with a presentation `label` (the raw `timestamp` resolved to a
// short date by the data layer).
//
// `low` is REQUIRED here though it is optional on the wire: it is plotted as a
// series, and AreaChart's `data` is `Record<K, number | null>`, which an optional
// property does not satisfy. Requiring it makes each host resolve the absent case
// (`p.low ?? 0`) rather than leaving a hole the chart would read as a gap.
export type FindingsChartPoint = Omit<FindingsTimeseriesPoint, 'timestamp' | 'low'> & {
  label: string;
  low: number;
};

export interface FindingsTimeseriesView {
  points: FindingsChartPoint[];
  /**
   * The width of one plotted point, which the SERVER chooses from the range
   * (day for 7d/30d, week for 3m/6m) and returns alongside the points. The
   * subtitle names it, so a hardcoded cadence there misreports a weekly bucket
   * as a daily one by a factor of seven.
   *
   * `null` is "not known yet" and drops the cadence clause entirely. The header
   * renders ABOVE the loading and error states, so a host with no response in
   * hand would otherwise have to invent a bucket width and have it displayed as
   * fact — guessing `day` under a 6m range reproduces exactly the mislabel this
   * prop exists to remove, for as long as the request is in flight.
   *
   * Nullable but REQUIRED, rather than optional: a default reads as safe at
   * every call site that omits it, which is every call site until somebody
   * remembers, while `null` is a decision the host has to write down.
   */
  granularity: TimeseriesGranularity | null;
  isLoading: boolean;
  error: string | null;
}

type FindingsSeriesKey = keyof Omit<FindingsTimeseriesPoint, 'timestamp'>;

const FINDINGS_SERIES: { key: FindingsSeriesKey; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: COLORS.sevCritical },
  { key: 'high', label: 'High', color: COLORS.sevHigh },
  { key: 'medium', label: 'Medium', color: COLORS.sevMedium },
  { key: 'low', label: 'Low', color: COLORS.sevLow },
];

export function FindingsOverTimeCardView({
  points,
  granularity,
  isLoading,
  error,
}: FindingsTimeseriesView) {
  // Every plotted series counts, `low` included — summing only the top three
  // renders "No findings" over a range that genuinely holds low-severity ones.
  // Derived from the plotted series rather than a hand-written sum, for two
  // reasons. A series added to FINDINGS_SERIES is counted here automatically. And
  // each value is tested for falsiness instead of added: `low` is OPTIONAL on the
  // wire and this package ships to hosts whose types are erased, so a three-series
  // producer reaches this — and summing an absent value yields NaN, which is not
  // `=== 0`, reporting a genuinely empty range as populated.
  const isEmpty = points.every((p) => FINDINGS_SERIES.every((s) => !p[s.key]));
  return (
    <Card className="mt-4 shadow-sm xl:mt-5">
      <CardHeader>
        <CardIcon>
          <AnalyticsIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Findings over time</CardTitle>
          {/* Built as one string rather than an inline conditional, so the space
              before "per" cannot go missing to JSX whitespace collapsing. */}
          <CardDescription>
            {`New sensitive-data detections${granularity === null ? '' : ` per ${granularity}`}`}
          </CardDescription>
        </CardHeading>
        <CardAction className="gap-3 text-xs text-text-2">
          {FINDINGS_SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span className="size-2 rounded-xs" style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </CardAction>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="pb-2">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : isEmpty ? (
          <WidgetEmpty message="No findings in this range." />
        ) : (
          <AreaChart data={points} series={FINDINGS_SERIES} height={160} />
        )}
      </CardContent>
    </Card>
  );
}
