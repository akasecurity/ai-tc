'use client';
// Required for two reasons. AreaChart's `valueFormat` prop below is a FUNCTION,
// used to format arbitrary interpolated tooltip values at hover time — not
// something that can be pre-formatted into strings server-side; Next's
// Server→Client boundary rejects a bare function prop, so this whole card must
// own the client boundary rather than let a server-rendered caller (web-ui's
// page.tsx) pass the function in. And the legend toggles which severities the
// chart plots, so this card owns visibility state.

import type { MttrTrendPoint } from '@akasecurity/schema';
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
import { ClockIcon } from '../shared/icons.tsx';
import { SeriesLegend, useSeriesVisibility } from '../shared/SeriesLegend.tsx';
import { formatMttrDuration } from './format.ts';
import { WidgetEmpty, WidgetError } from './widget-shared.tsx';

// One bucket's point with a presentation `label` (the raw `timestamp` resolved
// to a short date by the data layer — mirrors FindingsChartPoint) plus the raw
// per-severity mean MTTR in ms. Nullability is carried straight through from
// the contract: `null` means no `fixed-at-source` resolutions fell in that
// bucket for that severity, not zero.
export type MttrChartPoint = MttrTrendPoint['bySeverity'] & { label: string };

export interface MttrTrendView {
  points: MttrChartPoint[];
  isLoading: boolean;
  error: string | null;
}

type MttrSeriesKey = keyof MttrTrendPoint['bySeverity'];

const MTTR_SERIES: { key: MttrSeriesKey; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: COLORS.sevCritical },
  { key: 'high', label: 'High', color: COLORS.sevHigh },
  { key: 'medium', label: 'Medium', color: COLORS.sevMedium },
  { key: 'low', label: 'Low', color: COLORS.sevLow },
];

export function MttrTrendCardView({ points, isLoading, error }: MttrTrendView) {
  // Derived from the plotted series rather than hand-listing the four
  // severities, so one added to MTTR_SERIES is accounted for here too. It
  // tests for null rather than falsiness because 0 is a real reading here
  // ("resolved instantly"), unlike a count.
  const isEmpty = points.every((p) => MTTR_SERIES.every((s) => p[s.key] === null));
  const latest = points.at(-1) ?? null;
  // The chart is handed only the visible series, while `isEmpty` above stays
  // over ALL of them: the empty state describes the range, not the filter.
  const visibility = useSeriesVisibility(MTTR_SERIES);
  // Must stay equal to the condition the AreaChart below renders under.
  const chartShown = !error && !isLoading && !isEmpty;

  return (
    <Card className="mt-4 shadow-sm xl:mt-5">
      <CardHeader>
        <CardIcon>
          <ClockIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Time to remediate</CardTitle>
          <CardDescription>Mean time from detection to resolution, by severity</CardDescription>
        </CardHeading>
        <CardAction className="gap-3 text-xs text-text-2">
          <SeriesLegend
            series={MTTR_SERIES}
            visibility={visibility}
            interactive={chartShown}
            metaLabel={(key) => (latest === null ? null : formatMttrDuration(latest[key]))}
          />
        </CardAction>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="pb-2">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : isEmpty ? (
          <WidgetEmpty message="No resolved findings in this range." />
        ) : (
          <AreaChart
            // Passed straight through rather than copied: AreaChart reads a
            // null series value as a GAP in the line and skips it in the
            // tooltip, so a no-data bucket reads as "no data" rather than a
            // misleading 0ms. The legend reads the same raw latest bucket, so
            // a genuinely-no-data severity shows "—" there too.
            data={points}
            series={visibility.visible}
            height={160}
            valueFormat={formatMttrDuration}
          />
        )}
      </CardContent>
    </Card>
  );
}
