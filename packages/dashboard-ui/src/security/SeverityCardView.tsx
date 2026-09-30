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
import { COMBINED_STATUS_COLUMNS, SPLIT_STATUS_COLUMNS, statusHrefKey } from './status-columns.ts';
import { compactCount, numberFormat, WidgetEmpty, WidgetError } from './widget-shared.tsx';

// Props = the data the connected wrapper's hook (or a server fetch) produces.
// `bySeverity` is expected pre-normalized to display order (zero-filled).
//
// The card is a severity x status matrix. Rows are severities, columns are the
// disjoint lifecycle buckets (`openAtRest`, `handled`, `resolved`, `dismissed`) and
// the grand total is the sum of the rows. A row's cells can sum to less than its
// `count`: untracked legacy at-rest findings are counted in `count` only. A
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
  const exact = numberFormat.format(value);
  const compact = value >= COMPACT_FROM;
  // The short form is for the eye; the exact figure is what assistive tech reads and
  // what a pointer sees on hover.
  const text = compact ? (
    <>
      <span aria-hidden>{compactCount(value)}</span>
      <span className="sr-only">{exact}</span>
    </>
  ) : (
    exact
  );
  const title = compact ? exact : undefined;
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

const MAX_TINT_PERCENT = 55;
// A non-zero cell never rounds down to an invisible tint, or it would read as emptier
// than a zero cell (which keeps the neutral background).
const MIN_TINT_PERCENT = 6;

// Cell shading scales with the cell's share of the largest cell, tinted with the
// row's own severity hue. Text stays `text-text` on top: the tint is capped so it
// never becomes a fill the text cannot be read against.
function tint(color: string, count: number, max: number): string | undefined {
  if (count <= 0 || max <= 0) return undefined;
  const pct = String(Math.max(MIN_TINT_PERCENT, Math.round((count / max) * MAX_TINT_PERCENT)));
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}

// The loading state is laid out with the same table classes as the loaded matrix
// (four severity rows, the status columns plus All, and the footer row), so the card
// keeps its size and columns when the data arrives. The status columns are assumed to
// be the split set, which is what a current producer sends.
function MatrixSkeleton() {
  const statusCells = SPLIT_STATUS_COLUMNS.length;
  return (
    <table aria-hidden className="w-full border-separate border-spacing-1 text-ui">
      <thead>
        <tr>
          <th />
          {Array.from({ length: statusCells + 1 }, (_, i) => (
            <th key={i} className="px-1 pb-2">
              <Skeleton className="ml-auto h-3 w-12" />
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {[0, 1, 2, 3].map((row) => (
          <tr key={row}>
            <th className="pr-2 text-left">
              <Skeleton className="h-4 w-16" />
            </th>
            {Array.from({ length: statusCells }, (_, i) => (
              <td key={i} className="p-0">
                <Skeleton className="h-9 w-full" />
              </td>
            ))}
            <td className="p-0">
              <Skeleton className="ml-auto h-4 w-8" />
            </td>
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr>
          <th className="pr-2 text-left">
            <Skeleton className="h-4 w-6" />
          </th>
          {Array.from({ length: statusCells }, (_, i) => (
            <td key={i} className="p-0">
              <Skeleton className="ml-auto h-4 w-8" />
            </td>
          ))}
          <td className="p-0">
            <Skeleton className="ml-auto h-4 w-10" />
          </td>
        </tr>
      </tfoot>
    </table>
  );
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
  const columns = !hasStatus ? [] : hasSplit ? SPLIT_STATUS_COLUMNS : COMBINED_STATUS_COLUMNS;
  const max = Math.max(0, ...bySeverity.flatMap((s) => columns.map((c) => c.pick(s))));
  const columnTotals = columns.map((c) => ({
    column: c,
    n: bySeverity.reduce((sum, s) => sum + c.pick(s), 0),
  }));
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
          {columnTotals.map(({ column, n }) => (
            <td key={column.key} className="p-0 text-right text-text-2">
              <Count
                value={n}
                href={statusHrefs?.[statusHrefKey('all', column.key)]}
                label={column.label.toLowerCase()}
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
          <MatrixSkeleton />
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
