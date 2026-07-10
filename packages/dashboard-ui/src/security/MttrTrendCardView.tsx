'use client';
// Required (unlike the other card views here): AreaChart's `valueFormat`
// prop below is a FUNCTION, used to format arbitrary interpolated tooltip
// values at hover time — not something that can be pre-formatted into
// strings server-side. Next's Server→Client boundary rejects a bare function
// prop, so this whole card must own the client boundary rather than let a
// server-rendered caller (web-ui's page.tsx) pass the function in.

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
  const isEmpty = points.every(
    (p) => p.critical === null && p.high === null && p.medium === null && p.low === null,
  );
  // AreaChart supports nullable series values (null → a GAP in the line, and
  // skipped in the tooltip), so pass the raw per-severity MTTR straight
  // through: a no-data bucket must read as "no data", never a misleading 0ms
  // ("resolved instantly"). The legend below reads the same raw latest bucket,
  // so a genuinely-no-data severity shows "—" there too.
  const chartData = points.map((p) => ({
    label: p.label,
    critical: p.critical,
    high: p.high,
    medium: p.medium,
    low: p.low,
  }));
  const latest = points.at(-1) ?? null;

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
          {MTTR_SERIES.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <span className="size-2 rounded-xs" style={{ background: s.color }} />
              {s.label}
              {latest && <span className="text-text-3">{formatMttrDuration(latest[s.key])}</span>}
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
          <WidgetEmpty message="No resolved findings in this range." />
        ) : (
          <AreaChart
            data={chartData}
            series={MTTR_SERIES}
            height={160}
            valueFormat={formatMttrDuration}
          />
        )}
      </CardContent>
    </Card>
  );
}
