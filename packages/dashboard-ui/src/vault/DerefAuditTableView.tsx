'use client';
import type { VaultDeref, VaultDerefOutcome } from '@akasecurity/schema';
import { isBatchedDerefReason } from '@akasecurity/schema';
import {
  Badge,
  Button,
  cn,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';

import { relativeTime } from '../lib/relativeTime.ts';
import { DEREF_REASON_LABEL } from './atoms.tsx';

export interface DerefAuditTableViewProps {
  rows: VaultDeref[];
  // How many display/view-render rows the caller's query hid. Counted over the
  // whole trail, not the page — the toggle below reveals all of them, not the
  // ones that happen to fall inside the rows loaded so far.
  hiddenBatched: number;
  showBatched: boolean;
  onToggleBatched?: (showBatched: boolean) => void;
  // Whether the trail holds resolutions older than the ones passed in.
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  onNextPage?: (() => void) | undefined;
  onPreviousPage?: (() => void) | undefined;
  loadingNextPage?: boolean;
  // 1-based position of this window's first row in the whole trail.
  pageStart?: number | undefined;
  /**
   * The instant this render is measured against, in epoch milliseconds. The host
   * captures one and every relative label below reads it. Required: a view that
   * picks its own instant renders one string while the server renders it and
   * another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
}

// Model-target crossings are the anomaly signal this trail exists for, so both
// their outcomes render loud: a revealed crossing means the raw value reached
// the model; a refused one means something tried and was stopped — the row that
// must never read as noise.
const MODEL_ROW_CLASS: Partial<Record<VaultDerefOutcome, string>> = {
  revealed: 'border-l-2 border-l-sev-critical bg-sev-critical-fill font-medium',
  refused: 'border-l-2 border-l-sev-high bg-sev-high-fill font-medium',
};

function OutcomeBadge({ row }: { row: VaultDeref }) {
  if (row.target === 'model' && row.outcome === 'revealed') {
    return <Badge variant="critical">revealed</Badge>;
  }
  if (row.outcome === 'refused') return <Badge variant="high">refused</Badge>;
  if (row.outcome === 'unavailable') return <Badge variant="outline">unavailable</Badge>;
  return <Badge variant="default">revealed</Badge>;
}

/**
 * The de-reference audit trail — one row per resolution of a vaulted value
 * (never the value itself). Display/view-render rows are batched one-per-render
 * and hidden by default so the model crossings stay visible; purge rows record
 * that entries were destroyed and their pointers made unresolvable.
 */
export function DerefAuditTableView({
  rows,
  hiddenBatched,
  showBatched,
  onToggleBatched,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  loadingNextPage = false,
  pageStart,
  renderedAt,
}: DerefAuditTableViewProps) {
  const toggle =
    onToggleBatched === undefined ? null : (
      <Button
        variant="link"
        tone="neutral"
        onClick={() => {
          onToggleBatched(!showBatched);
        }}
      >
        {showBatched ? 'Hide display/render resolutions' : 'Show them'}
      </Button>
    );
  const hiddenLine =
    !showBatched && hiddenBatched > 0 ? (
      <p className="mt-3 flex items-center gap-2 text-xs text-text-3">
        <span>
          {String(hiddenBatched)} display/render{' '}
          {hiddenBatched === 1 ? 'resolution' : 'resolutions'} hidden
        </span>
        {toggle}
      </p>
    ) : showBatched && onToggleBatched !== undefined ? (
      <p className="mt-3 text-xs text-text-3">{toggle}</p>
    ) : null;

  // See VaultInventoryView. This trail is append-only and never purged, so an
  // empty later page is not reachable here the way it is on the other two lists
  // — but the pager is wired the same way, and a view that strands the reader
  // when its list does start losing rows is the wrong thing to leave behind.
  const isEmpty = rows.length === 0;
  if (isEmpty && !hasPreviousPage && !hasNextPage) {
    return (
      <div className="rounded-xl border border-border bg-surface p-4">
        <div className="py-10 text-center text-sm text-text-3">
          No de-references recorded — every resolution of a vaulted value lands here.
        </div>
        {hiddenLine}
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-surface p-4">
      {isEmpty ? (
        <div className="py-10 text-center text-sm text-text-3">
          These rows moved while you were reading. Step back to see the rest.
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>When</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Outcome</TableHead>
              <TableHead>Grant</TableHead>
              <TableHead>Pointers</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) =>
              row.reason === 'purge' ? (
                // A purge is an event, not a de-reference: render it as one
                // distinguished line — the record that values were destroyed
                // outlives the values.
                <TableRow key={row.id} data-purge="" className="bg-surface-2">
                  <TableCell className="text-xs text-text-2">
                    {relativeTime(row.at, renderedAt)}
                  </TableCell>
                  <TableCell colSpan={5} className="text-xs font-medium text-text-2">
                    Vault purge —{' '}
                    {row.pointerCount === 1 ? 'a pointer' : `${String(row.pointerCount)} pointers`}{' '}
                    made permanently unresolvable
                  </TableCell>
                </TableRow>
              ) : (
                <TableRow
                  key={row.id}
                  data-model-crossing={row.target === 'model' ? row.outcome : undefined}
                  className={cn(
                    row.target === 'model' && MODEL_ROW_CLASS[row.outcome],
                    isBatchedDerefReason(row.reason) && 'text-text-3',
                  )}
                >
                  <TableCell className="text-xs text-text-2">
                    {relativeTime(row.at, renderedAt)}
                  </TableCell>
                  <TableCell className="text-xs">{DEREF_REASON_LABEL[row.reason]}</TableCell>
                  <TableCell className="text-xs">
                    {row.target === 'model' ? (
                      <span className="font-semibold text-sev-critical-ink">model</span>
                    ) : (
                      <span className="text-text-2">human</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <OutcomeBadge row={row} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-text-3">
                    {row.grantId === undefined ? '—' : row.grantId.slice(0, 8)}
                  </TableCell>
                  <TableCell className="text-xs text-text-2">
                    {row.pointerCount > 1 ? `×${String(row.pointerCount)}` : '—'}
                  </TableCell>
                </TableRow>
              ),
            )}
          </TableBody>
        </Table>
      )}
      {onNextPage ? (
        <Pagination>
          <PaginationPrevious
            disabled={!hasPreviousPage || loadingNextPage}
            onClick={onPreviousPage}
          />
          <PaginationStatus>
            {pageStart === undefined
              ? `${String(rows.length)} shown`
              : isEmpty
                ? '0 resolutions'
                : `${String(pageStart)}–${String(pageStart + rows.length - 1)} resolutions`}
          </PaginationStatus>
          <PaginationNext
            disabled={!hasNextPage || loadingNextPage}
            loading={loadingNextPage}
            onClick={onNextPage}
          />
        </Pagination>
      ) : (
        hasNextPage && (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing the most recent {rows.length} resolutions.
          </p>
        )
      )}
      {hiddenLine}
    </div>
  );
}
