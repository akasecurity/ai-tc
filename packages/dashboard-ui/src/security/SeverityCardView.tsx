'use client';
import type { Severity, SeveritySummaryItem } from '@akasecurity/schema';
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

import { AlertOctagonIcon } from '../shared/icons.tsx';
import { SEVERITY_META } from './meta.ts';
import { statusHrefKey } from './status-href-key.ts';
import { compactCount, numberFormat, WidgetEmpty, WidgetError } from './widget-shared.tsx';

// Props = the data the connected wrapper's hook (or a server fetch) produces.
// `bySeverity` is expected pre-normalized to display order (zero-filled).
//
// The card is a severity x status matrix. Rows are severities, columns are the
// lifecycle buckets (`openAtRest`, `handled`, `resolved`, `dismissed`), which are disjoint, so
// every row sums to its `count` and the grand total is the sum of the rows. A
// count-only response carries no buckets: the status columns are then omitted and
// only the severity totals render.
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
  /**
   * Deep links for the status cells, keyed by `statusHrefKey`: a severity (or
   * `all` for the footer row) against a status column (or `all` for the row total,
   * which with `all` too is the grand total). Plain strings rather than a function
   * because the host is a server component and this one is a client component.
   * A cell with no entry, or a count of 0, renders as plain text.
   */
  statusHrefs?: Record<string, string> | undefined;
}

// From this size up a count is shown short (`12k`) so a five-digit cell cannot
// widen its column; the exact figure stays on `title`.
const COMPACT_FROM = 10_000;

function Count({
  value,
  href,
  label,
}: {
  value: number;
  href?: string | undefined;
  label: string;
}) {
  const compact = value >= COMPACT_FROM;
  const text = compact ? compactCount(value) : numberFormat.format(value);
  const title = compact ? numberFormat.format(value) : undefined;
  if (href && value > 0) {
    return (
      <a
        href={href}
        title={title ? `${title} · View ${label} findings` : `View ${label} findings`}
        className="block rounded-sm px-2 py-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
      >
        {text}
      </a>
    );
  }
  return (
    <span title={title} className="block px-2 py-2">
      {text}
    </span>
  );
}

interface StatusColumn {
  key: string;
  label: string;
  pick: (s: SeveritySummaryItem) => number;
}

const OPEN: StatusColumn = { key: 'open', label: 'Open', pick: (s) => s.openAtRest ?? 0 };
const DISMISSED: StatusColumn = {
  key: 'dismissed',
  label: 'Dismissed',
  pick: (s) => s.dismissed ?? 0,
};

// A response that carries `caught` but not its two halves (an older producer) gets
// one combined column rather than a `Handled`/`Resolved` pair of zeros.
const SPLIT_COLUMNS: StatusColumn[] = [
  OPEN,
  { key: 'handled', label: 'Handled', pick: (s) => s.handled ?? 0 },
  { key: 'resolved', label: 'Resolved', pick: (s) => s.resolved ?? 0 },
  DISMISSED,
];
const COMBINED_COLUMNS: StatusColumn[] = [
  OPEN,
  { key: 'caught', label: 'Caught', pick: (s) => s.caught ?? 0 },
  DISMISSED,
];

const MAX_TINT_PERCENT = 55;

// Cell shading scales with the cell's share of the largest cell, tinted with the
// row's own severity hue. Text stays `text-text` on top: the tint is capped so it
// never becomes a fill the text cannot be read against.
function tint(color: string, count: number, max: number): string | undefined {
  if (count <= 0 || max <= 0) return undefined;
  const pct = String(Math.round((count / max) * MAX_TINT_PERCENT));
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}

function Matrix({
  bySeverity,
  total,
  severityHrefs,
  statusHrefs,
}: {
  bySeverity: SeveritySummaryItem[];
  total: number;
  severityHrefs: SeveritySummaryView['severityHrefs'];
  statusHrefs: SeveritySummaryView['statusHrefs'];
}) {
  const hasStatus = bySeverity.some(
    (s) =>
      s.handled !== undefined ||
      s.resolved !== undefined ||
      s.caught !== undefined ||
      s.openAtRest !== undefined ||
      s.dismissed !== undefined,
  );
  const hasSplit = bySeverity.some((s) => s.handled !== undefined || s.resolved !== undefined);
  const columns = !hasStatus ? [] : hasSplit ? SPLIT_COLUMNS : COMBINED_COLUMNS;
  const max = Math.max(0, ...bySeverity.flatMap((s) => columns.map((c) => c.pick(s))));
  const columnTotals = columns.map((c) => bySeverity.reduce((n, s) => n + c.pick(s), 0));
  const head = 'px-1 pb-2 text-right text-label font-semibold uppercase tracking-wide text-text-3';

  return (
    <table className="w-full border-separate border-spacing-1 text-ui">
      <thead>
        <tr>
          <th scope="col" className="sr-only">
            Severity
          </th>
          {columns.map((c) => (
            <th key={c.key} scope="col" className={head}>
              {c.label}
            </th>
          ))}
          <th scope="col" className={head}>
            All
          </th>
        </tr>
      </thead>
      <tbody>
        {bySeverity.map((s) => {
          const meta = SEVERITY_META[s.severity];
          const href = severityHrefs?.[s.severity];
          const label = (
            <>
              <span className="size-2 shrink-0 rounded-xs" style={{ background: meta.color }} />
              {meta.label}
            </>
          );
          return (
            <tr key={s.severity}>
              <th scope="row" className="pr-2 text-left font-semibold text-text">
                {href ? (
                  <a
                    href={href}
                    title={`View ${meta.label.toLowerCase()} findings`}
                    className="flex items-center gap-2 rounded-sm hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                  >
                    {label}
                  </a>
                ) : (
                  <span className="flex items-center gap-2">{label}</span>
                )}
              </th>
              {columns.map((c) => {
                const n = c.pick(s);
                return (
                  <td
                    key={c.key}
                    data-cell={`${s.severity}-${c.key}`}
                    className="rounded-sm bg-surface-2 p-0 text-right font-bold text-text"
                    style={{ backgroundColor: tint(meta.color, n, max) }}
                  >
                    <Count
                      value={n}
                      href={statusHrefs?.[statusHrefKey(s.severity, c.key)]}
                      label={`${meta.label.toLowerCase()} ${c.label.toLowerCase()}`}
                    />
                  </td>
                );
              })}
              <td className="p-0 text-right text-text-2">
                <Count value={s.count} href={href} label={meta.label.toLowerCase()} />
              </td>
            </tr>
          );
        })}
      </tbody>
      <tfoot>
        <tr>
          <th scope="row" className="pr-2 text-left font-normal text-text-2">
            All
          </th>
          {columnTotals.map((n, i) => (
            <td key={columns[i]?.key} className="p-0 text-right text-text-2">
              <Count
                value={n}
                href={statusHrefs?.[statusHrefKey('all', columns[i]?.key ?? '')]}
                label={(columns[i]?.label ?? '').toLowerCase()}
              />
            </td>
          ))}
          <td className="p-0 text-right font-bold text-text">
            <Count value={total} href={statusHrefs?.[statusHrefKey('all', 'all')]} label="all" />
          </td>
        </tr>
      </tfoot>
    </table>
  );
}

export function SeverityCardView({
  bySeverity,
  total,
  severityHrefs,
  statusHrefs,
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
          <CardTitle>Findings by severity and status</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading…' : error ? '—' : `${numberFormat.format(total)} findings`}
          </CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading}>
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <div className="flex flex-col gap-2">
            {[0, 1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : total === 0 ? (
          <WidgetEmpty message="No findings." />
        ) : (
          <Matrix
            bySeverity={bySeverity}
            total={total}
            severityHrefs={severityHrefs}
            statusHrefs={statusHrefs}
          />
        )}
      </CardContent>
    </Card>
  );
}
