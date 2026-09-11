import type { Severity, SeveritySummaryItem } from '@akasecurity/schema';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  cn,
  Skeleton,
} from '@akasecurity/ui-kit';

import { Donut } from '../shared/charts.tsx';
import { AlertOctagonIcon } from '../shared/icons.tsx';
import { SEVERITY_META } from './meta.ts';
import { compactCount, numberFormat, WidgetEmpty, WidgetError } from './widget-shared.tsx';

// Props = the data the connected wrapper's hook (or a server fetch) produces.
// `bySeverity` is expected pre-normalized to display order (zero-filled).
//
// The card reports ONE measure: how many findings there are, by severity. The
// ring, the centre figure and the legend are three renderings of that same
// number, so any two of them can be read against each other — with one caveat:
// the centre is ROUNDED (compactCount), so at a boundary it reads `10k` over a
// legend summing to 9,999. The unrounded total is the CardDescription's text.
//
// It carried a lifecycle cut as well — a `caught` ring under a `caught` centre,
// above a `needs remediation` row and a legend of totals — which put three different
// populations in one card: a reader who took the legend as the breakdown of
// "needs remediation" was out by every finding the plugin caught in flight.
// The lifecycle split still exists where it can be read on its own terms
// (`aka stats` renders caught vs needs-remediation from the same store fields).
export interface SeveritySummaryView {
  bySeverity: SeveritySummaryItem[];
  total: number;
  isLoading: boolean;
  error: string | null;
  /**
   * Per-severity deep link (the findings page filtered to that severity).
   * Host-supplied so this package stays router-agnostic; a severity with no entry
   * renders as plain text.
   */
  severityHrefs?: Partial<Record<Severity, string>> | undefined;
}

export function SeverityCardView({
  bySeverity,
  total,
  severityHrefs,
  isLoading,
  error,
}: SeveritySummaryView) {
  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon tone="critical">
          <AlertOctagonIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>By severity</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading…' : error ? '—' : `${numberFormat.format(total)} findings`}
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
          <WidgetEmpty message="No findings." />
        ) : (
          <>
            <Donut
              // The same per-severity counts the legend lists, so the ring is a
              // picture of the rows beside it and the centre is their sum.
              segments={bySeverity.map((s) => ({
                label: SEVERITY_META[s.severity].label,
                value: s.count,
                color: SEVERITY_META[s.severity].color,
              }))}
              size={120}
              thickness={15}
            >
              {/* Compact in the ring: the centre is a 90px hole and a six-figure
                  total would wrap or overflow it. compactCount rounds across its
                  own boundary (9,999 reads `10k`), so the exact number has to stay
                  reachable — that is the CardDescription above, which renders it as
                  TEXT for every reader. The title here is a pointer-only
                  convenience and can never be the only copy: a `title` on a
                  non-focusable div is unreachable by keyboard and absent on touch.
                  Both formatters pin en-US, so neither is a hydration mismatch. */}
              <div
                className="font-display text-2xl font-semibold leading-none text-text"
                title={numberFormat.format(total)}
              >
                {compactCount(total)}
              </div>
            </Donut>
            <div className="flex flex-1 flex-col gap-2">
              {bySeverity.map((s) => {
                const href = severityHrefs?.[s.severity];
                const Row = href ? 'a' : 'div';
                return (
                  <Row
                    key={s.severity}
                    {...(href
                      ? {
                          href,
                          title: `View ${SEVERITY_META[s.severity].label.toLowerCase()} findings`,
                        }
                      : {})}
                    className={cn(
                      'flex items-center gap-2',
                      href &&
                        '-mx-1 rounded-sm px-1 transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary/40',
                    )}
                  >
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
                  </Row>
                );
              })}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
