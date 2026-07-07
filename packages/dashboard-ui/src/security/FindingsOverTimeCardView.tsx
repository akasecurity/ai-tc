import type { FindingsTimeseriesPoint } from '@akasecurity/schema';
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
export type FindingsChartPoint = Omit<FindingsTimeseriesPoint, 'timestamp'> & { label: string };

export interface FindingsTimeseriesView {
  points: FindingsChartPoint[];
  isLoading: boolean;
  error: string | null;
}

type FindingsSeriesKey = keyof Omit<FindingsTimeseriesPoint, 'timestamp'>;

const FINDINGS_SERIES: { key: FindingsSeriesKey; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: COLORS.sevCritical },
  { key: 'high', label: 'High', color: COLORS.sevHigh },
  { key: 'medium', label: 'Medium', color: COLORS.sevMedium },
];

export function FindingsOverTimeCardView({ points, isLoading, error }: FindingsTimeseriesView) {
  const isEmpty = points.every((p) => p.critical + p.high + p.medium === 0);
  return (
    <Card className="mt-4 shadow-sm xl:mt-5">
      <CardHeader>
        <CardIcon>
          <AnalyticsIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Findings over time</CardTitle>
          <CardDescription>New sensitive-data detections per day</CardDescription>
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
