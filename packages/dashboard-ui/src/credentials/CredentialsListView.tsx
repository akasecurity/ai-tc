'use client';
import { CredentialStatus } from '@akasecurity/schema';
import {
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

import { Ico } from '../inventory/Ico.tsx';
import { relativeTime } from '../lib/relativeTime.ts';
import { SearchField } from '../shared/SearchField.tsx';
import { CredentialStatusBadge } from './CredentialStatusBadge.tsx';
import { credentialDismissReasonLabel } from './dismissal.ts';
import { credentialLabel, credentialName } from './name.ts';
import { CREDENTIAL_STATUS, credentialStatusState } from './status.ts';
import type { CredentialListItem, CredentialStatusCounts } from './types.ts';

export interface CredentialsListViewProps {
  items: CredentialListItem[];
  /** Credentials matching the search and the status chip across every page. */
  total: number;
  /**
   * The status chip that is on; null is All. Pass it with `onStatus`: without
   * chips the reader has no way back to All, so the view then ignores it.
   */
  status?: CredentialStatus | null | undefined;
  /** Picks a chip; null is All. Omit it and no chips are shown. */
  onStatus?: ((status: CredentialStatus | null) => void) | undefined;
  /**
   * Each chip's own count under the current search, whatever chip is on.
   * Undefined while the host does not know them; the chips then show no count.
   */
  statusCounts?: CredentialStatusCounts | undefined;
  /**
   * The current query. A new query must start again at the first page: the view
   * reads an empty page with a cursor either side as rows that moved, not as a
   * search that matched nothing.
   */
  search: string;
  onSearch: (value: string) => void;
  /** Whether the list shows the dismissed credentials instead of the others. */
  dismissed?: boolean | undefined;
  /** How many credentials matching the search are dismissed, shown on the Dismissed toggle. */
  dismissedCount?: number | undefined;
  /**
   * Shows or leaves the dismissed credentials. Omit it and no Dismissed toggle
   * is shown. A change starts again at the first page.
   */
  onDismissedChange?: ((dismissed: boolean) => void) | undefined;
  onSelect: (id: string) => void;
  onExport: () => void;
  exporting?: boolean | undefined;
  onNextPage: () => void;
  onPreviousPage: () => void;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  loadingPage?: boolean | undefined;
  /** 1-indexed position of `items[0]` in the whole result. */
  pageStart: number;
  isLoading?: boolean | undefined;
  /** Shown in place of the table, the count and Export when the host cannot read the list. */
  error?: string | undefined;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
}

const COLUMNS = [
  'Name',
  'Provider',
  'Owner',
  'Projects',
  'Teams',
  'Endpoints',
  'Last rotated',
  'Status',
] as const;
const NUMERIC = new Set<string>(['Projects', 'Teams', 'Endpoints']);
/** The filter row's chip, matching the pills the inventory table filters with. */
const chipClass = (on: boolean) =>
  cn(
    'inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-full border px-3 py-1 text-xs font-semibold transition-colors',
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
    on
      ? 'border-primary bg-primary-tint text-primary'
      : 'border-border bg-surface text-text-2 hover:text-text',
  );
/** The first and last cell line up with the header and filter rows above them. */
// Keyed by position, not by name like `NUMERIC`: a gutter belongs to whichever
// column sits at the row's edge, while alignment belongs to the column itself.
const edgeClass = (index: number) =>
  index === 0 ? 'pl-5' : index === COLUMNS.length - 1 ? 'pr-5' : '';

/** The credential ledger: one row per detected value, newest first. */
export function CredentialsListView({
  items,
  total,
  status: statusProp = null,
  onStatus,
  statusCounts,
  search,
  onSearch,
  dismissed = false,
  dismissedCount,
  onDismissedChange,
  onSelect,
  onExport,
  exporting = false,
  onNextPage,
  onPreviousPage,
  hasNextPage,
  hasPreviousPage,
  loadingPage = false,
  pageStart,
  isLoading = false,
  error,
  renderedAt,
}: CredentialsListViewProps) {
  const status = onStatus === undefined ? null : statusProp;
  const refused = error !== undefined;
  const loadingEmpty = isLoading && items.length === 0;
  // An empty page past the first means rows moved under the cursor, not an empty ledger.
  const emptyLedger = items.length === 0 && !hasPreviousPage && !hasNextPage;
  const filters = onStatus !== undefined || onDismissedChange !== undefined;
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex flex-wrap items-center gap-3.5 border-b border-border px-5 py-4">
        <span className="grid size-10 shrink-0 place-items-center rounded-lg bg-sev-high-fill text-sev-high-ink">
          <Ico name="key" className="size-5" />
        </span>
        <div className="min-w-40 flex-1">
          <div className="font-display text-base font-semibold">Credentials</div>
          <div className="mt-px text-xs text-text-3">
            {refused
              ? 'Not available'
              : isLoading
                ? '…'
                : `${String(total)} ${total === 1 ? 'credential' : 'credentials'}`}
          </div>
        </div>
        <SearchField
          className="h-9 w-full max-w-80 sm:w-72"
          surface="card"
          label="Search credentials"
          placeholder="Search credentials…"
          value={search}
          onValueChange={onSearch}
        />
        <Button variant="outline" size="md" disabled={exporting || refused} onClick={onExport}>
          Export
        </Button>
      </div>

      {filters && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
          {onStatus !== undefined && (
            <StatusChips
              status={status}
              onStatus={onStatus}
              counts={refused || isLoading ? undefined : statusCounts}
            />
          )}
          {onStatus !== undefined && onDismissedChange !== undefined && (
            <span aria-hidden className="mx-0.5 h-5 w-px bg-border" />
          )}
          {onDismissedChange !== undefined && (
            <button
              type="button"
              aria-pressed={dismissed}
              className={chipClass(dismissed)}
              onClick={() => {
                onDismissedChange(!dismissed);
              }}
            >
              Dismissed
              {dismissedCount !== undefined && (
                <span className="tabular-nums opacity-70">{String(dismissedCount)}</span>
              )}
            </button>
          )}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {refused ? (
          <p role="alert" className="px-5 py-10 text-center text-sm text-sev-critical-ink">
            {error}
          </p>
        ) : loadingEmpty ? (
          <div className="flex flex-col gap-2 px-5 py-4">
            {Array.from({ length: 8 }, (_, i) => (
              <div key={i} className="h-11 animate-pulse rounded-md bg-surface-3" />
            ))}
          </div>
        ) : items.length === 0 ? (
          <p className="px-5 py-10 text-center text-sm text-text-3">
            {!emptyLedger
              ? 'These rows moved while you were reading. Step back to see the rest.'
              : status !== null
                ? `No credentials are ${credentialStatusState(status)}${search.trim() === '' ? '.' : ' in this search.'}`
                : search.trim() !== ''
                  ? 'Nothing matches this search.'
                  : dismissed
                    ? 'No credentials are dismissed.'
                    : 'No credentials have been seen yet. They appear here once an attached machine shares a sighting.'}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                {COLUMNS.map((column, index) => (
                  <TableHead
                    key={column}
                    className={cn('pt-3', NUMERIC.has(column) && 'text-right', edgeClass(index))}
                  >
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow
                  key={item.id}
                  className="cursor-pointer hover:bg-surface-2"
                  aria-label={`View credential ${credentialName(item).text}`}
                  onClick={() => {
                    onSelect(item.id);
                  }}
                >
                  <TableCell className={edgeClass(0)}>
                    <div
                      className={cn(
                        'max-w-64 truncate text-xs font-semibold text-text',
                        credentialName(item).isVariable && 'font-mono',
                      )}
                      title={credentialName(item).text}
                    >
                      {credentialName(item).text}
                    </div>
                    <div className="max-w-64 truncate text-xs text-text-3">
                      {item.kind}
                      {credentialLabel(item) !== null && item.variableName !== null && (
                        <span className="font-mono"> · {item.variableName}</span>
                      )}
                      {item.dismissal !== null && (
                        <span>
                          {' '}
                          · Dismissed: {credentialDismissReasonLabel(item.dismissal.reason)}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{item.provider ?? '—'}</TableCell>
                  <TableCell className="text-xs text-text-2">{item.owner ?? '—'}</TableCell>
                  <TableCell className="text-right text-xs tabular-nums">
                    {String(item.projectCount)}
                  </TableCell>
                  <TableCell className="text-right text-xs tabular-nums">
                    {String(item.teamCount)}
                  </TableCell>
                  <TableCell className="text-right text-xs tabular-nums">
                    {String(item.endpointCount)}
                  </TableCell>
                  <TableCell className="text-xs text-text-2">
                    {item.lastRotated === null ? '—' : relativeTime(item.lastRotated, renderedAt)}
                  </TableCell>
                  <TableCell className={edgeClass(COLUMNS.length - 1)}>
                    <span className="inline-flex flex-wrap gap-1.5">
                      {item.statuses.map((s) => (
                        <CredentialStatusBadge key={s} status={s} />
                      ))}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {!refused && !loadingEmpty && !emptyLedger && (
        <Pagination className="justify-start gap-3 border-t border-border px-5 py-3">
          <PaginationStatus className="flex-1">
            {items.length === 0
              ? `${String(total)} in all`
              : `${String(pageStart)}–${String(pageStart + items.length - 1)} of ${String(total)}`}
          </PaginationStatus>
          <PaginationPrevious disabled={!hasPreviousPage || loadingPage} onClick={onPreviousPage} />
          <PaginationNext
            disabled={!hasNextPage || loadingPage}
            loading={loadingPage}
            onClick={onNextPage}
          />
        </Pagination>
      )}
    </div>
  );
}

function StatusChips({
  status,
  onStatus,
  counts,
}: {
  status: CredentialStatus | null;
  onStatus: (status: CredentialStatus | null) => void;
  counts: CredentialStatusCounts | undefined;
}) {
  const chips: { key: CredentialStatus | null; label: string; count: number | undefined }[] = [
    { key: null, label: 'All', count: counts?.all },
    ...CredentialStatus.options.map((key) => ({
      key,
      label: CREDENTIAL_STATUS[key].label,
      count: counts?.byStatus[key],
    })),
  ];
  return (
    <div role="group" aria-label="Filter by status" className="flex flex-wrap items-center gap-1.5">
      {chips.map((chip) => {
        const on = chip.key === status;
        return (
          <button
            key={chip.key ?? 'all'}
            type="button"
            aria-pressed={on}
            onClick={() => {
              onStatus(chip.key);
            }}
            className={chipClass(on)}
          >
            {chip.label}
            {chip.count !== undefined && (
              <span className="tabular-nums opacity-70">{String(chip.count)}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
