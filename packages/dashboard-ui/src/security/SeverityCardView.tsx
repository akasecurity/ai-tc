import type { SeveritySummaryItem } from '@akasecurity/schema';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  Skeleton,
} from '@akasecurity/ui-kit';

import { Donut } from '../shared/charts.tsx';
import { AlertOctagonIcon } from '../shared/icons.tsx';
import { SEVERITY_META } from './meta.ts';
import { numberFormat, WidgetEmpty, WidgetError } from './widget-shared.tsx';

// Props = the data the connected wrapper's hook (or a server fetch) produces.
// `bySeverity` is expected pre-normalized to display order (zero-filled).
// `needsRemediation` is optional/additive (absent until the resolution feature
// is wired end-to-end) — defaults to 0 so both feeders (this app's hook and the
// OSS web-ui's persistence spread) keep compiling either way.
export interface SeveritySummaryView {
  bySeverity: SeveritySummaryItem[];
  total: number;
  needsRemediation?: number;
  isLoading: boolean;
  error: string | null;
}

// True when the summary carries resolution-aware data — detected via the
// PER-SEVERITY `caught`/`openAtRest` fields, which a count-only feeder
// genuinely omits and NO hook fabricates. Deliberately does NOT key off a
// top-level `needsRemediation`: a dashboard hook (useSeveritySummary)
// historically coerced it to `0` on the count-only response, so a defined-`0`
// `needsRemediation` is NOT evidence of resolution data — keying off it would
// defeat the fallback on exactly the live count-only surface it must protect.
// When resolution data IS present, the persistence feeder populates the
// per-severity fields, so this fires correctly. Pure — unit-tested below.
export function hasResolutionData(view: {
  bySeverity: Pick<SeveritySummaryItem, 'caught' | 'openAtRest'>[];
}): boolean {
  return view.bySeverity.some((s) => s.caught !== undefined || s.openAtRest !== undefined);
}

export function SeverityCardView({
  bySeverity,
  total,
  needsRemediation,
  isLoading,
  error,
}: SeveritySummaryView) {
  // Legacy count-only feeders (no per-severity caught/openAtRest) fall back to
  // the pre-reframe "Open by severity" framing instead of asserting a
  // misleading "0 caught" / "Needs remediation: 0" on a security surface — see
  // hasResolutionData.
  const resolutionMode = hasResolutionData({ bySeverity });

  // Caught = handled in-flight (enforced). Sum the per-severity `caught` the
  // normalizer preserves rather than deriving `total - needsRemediation`: the
  // persistence layer increments total/count for EVERY row but excludes legacy
  // untracked at-rest rows (finding_key IS NULL) from BOTH caught and openAtRest,
  // so `total - needsRemediation` would silently over-count caught (understating
  // exposure) whenever such rows exist.
  const caught = bySeverity.reduce((sum, s) => sum + (s.caught ?? 0), 0);

  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon className="bg-sev-critical-fill text-sev-critical">
          <AlertOctagonIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>{resolutionMode ? 'By severity' : 'Open by severity'}</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading…' : error ? '—' : `${String(total)} findings`}
          </CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="flex items-center gap-4">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <>
            <Skeleton className="size-30 shrink-0 rounded-full" />
            <div className="flex flex-1 flex-col gap-2">
              {[0, 1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-4 w-full" />
              ))}
            </div>
          </>
        ) : total === 0 ? (
          <WidgetEmpty message={resolutionMode ? 'No findings.' : 'No open findings.'} />
        ) : (
          <>
            <Donut
              segments={bySeverity.map((s) => ({
                label: SEVERITY_META[s.severity].label,
                // The ring must encode the SAME population as the center
                // figure: per-severity caught under the "caught" headline
                // (an all-zero ring is honest — nothing caught yet), totals
                // under the legacy total/open center. Mixing them (totals
                // ring, caught center) overstated the caught share.
                value: resolutionMode ? (s.caught ?? 0) : s.count,
                color: SEVERITY_META[s.severity].color,
              }))}
              size={120}
              thickness={15}
            >
              <div>
                <div className="font-display text-2xl font-semibold leading-none text-text">
                  {numberFormat.format(resolutionMode ? caught : total)}
                </div>
                <div className="text-label text-text-3">{resolutionMode ? 'caught' : 'open'}</div>
              </div>
            </Donut>
            <div className="flex flex-1 flex-col gap-2">
              {resolutionMode ? (
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <span className="text-ui font-medium text-text-2">Needs remediation</span>
                  <span className="text-ui font-bold text-text">
                    {numberFormat.format(needsRemediation ?? 0)}
                  </span>
                </div>
              ) : null}
              {bySeverity.map((s) => (
                <div key={s.severity} className="flex items-center gap-2">
                  <span
                    className="size-2 rounded-xs"
                    style={{ background: SEVERITY_META[s.severity].color }}
                  />
                  <span className="flex-1 text-ui text-text-2">
                    {SEVERITY_META[s.severity].label}
                  </span>
                  <span className="text-ui font-bold text-text">
                    {numberFormat.format(s.count)}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
