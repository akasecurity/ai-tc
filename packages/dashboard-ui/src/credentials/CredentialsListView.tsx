'use client';
import {
  Button,
  Card,
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
import { credentialLabel, credentialName } from './name.ts';
import { credentialStatus } from './status.ts';
import type { CredentialListItem, CredentialStatus } from './types.ts';

export interface CredentialsListViewProps {
  items: CredentialListItem[];
  /**
   * Credentials matching the search and the status filter across every page:
   * the count behind the rows shown, which the header and the pager both
   * render. A total without the status filter applied pages over the wrong
   * count.
   */
  total: number;
  /**
   * The current query. A new query must start again at the first page: the view
   * reads an empty page with a cursor either side as rows that moved, not as a
   * search that matched nothing.
   */
  search: string;
  onSearch: (value: string) => void;
  /** The status the list is filtered to; null lists every credential. A new filter starts again at the first page. */
  status?: CredentialStatus | null | undefined;
  /** Omit it and no status filter is shown. */
  onStatusChange?: ((status: CredentialStatus | null) => void) | undefined;
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

const STATUS_FILTERS: readonly { value: CredentialStatus | null; label: string }[] = [
  { value: null, label: 'All' },
  { value: 'exposed', label: 'Exposed' },
  { value: 'ok', label: 'OK' },
];
const NUMERIC = new Set<string>(['Projects', 'Teams', 'Endpoints']);

/** The credential ledger: one row per detected value, newest first. */
export function CredentialsListView({
  items,
  total,
  search,
  onSearch,
  status = null,
  onStatusChange,
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
  const refused = error !== undefined;
  const loadingEmpty = isLoading && items.length === 0;
  // An empty page past the first means rows moved under the cursor, not an empty ledger.
  const emptyLedger = items.length === 0 && !hasPreviousPage && !hasNextPage;
  return (
    <Card className="flex flex-col gap-4 p-4 shadow-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-sev-high-fill text-sev-high-ink">
          <Ico name="key" className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="font-display text-sm font-semibold text-text">Credentials</div>
          <div className="text-xs text-text-3">
            {refused
              ? 'Not available'
              : isLoading
                ? '…'
                : `${String(total)} ${total === 1 ? 'credential' : 'credentials'}`}
          </div>
        </div>
        <SearchField
          className="ml-auto w-64"
          surface="card"
          label="Search credentials"
          placeholder="Search credentials…"
          value={search}
          onValueChange={onSearch}
        />
        <Button variant="outline" size="sm" disabled={exporting || refused} onClick={onExport}>
          Export
        </Button>
      </div>

      {onStatusChange !== undefined && (
        <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-1.5">
          {STATUS_FILTERS.map((f) => (
            <Button
              key={f.label}
              variant={status === f.value ? 'solid' : 'outline'}
              size="sm"
              aria-pressed={status === f.value}
              onClick={() => {
                onStatusChange(f.value);
              }}
            >
              {f.label}
            </Button>
          ))}
        </div>
      )}

      {refused ? (
        <p role="alert" className="py-10 text-center text-sm text-text-3">
          {error}
        </p>
      ) : loadingEmpty ? (
        <div className="flex flex-col gap-2 py-2">
          {Array.from({ length: 8 }, (_, i) => (
            <div key={i} className="h-11 animate-pulse rounded-md bg-surface-3" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <p className="py-10 text-center text-sm text-text-3">
          {!emptyLedger
            ? 'These rows moved while you were reading. Step back to see the rest.'
            : search.trim() !== ''
              ? 'Nothing matches this search.'
              : status !== null
                ? 'No credentials have this status.'
                : 'No credentials have been seen yet. They appear here once an attached machine shares a sighting.'}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {COLUMNS.map((column) => (
                  <TableHead key={column} className={cn(NUMERIC.has(column) && 'text-right')}>
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow
                  key={item.id}
                  className="cursor-pointer"
                  aria-label={`View credential ${credentialName(item).text}`}
                  onClick={() => {
                    onSelect(item.id);
                  }}
                >
                  <TableCell>
                    <div
                      className={cn(
                        'text-xs font-semibold text-text',
                        credentialName(item).isVariable && 'font-mono',
                      )}
                    >
                      {credentialName(item).text}
                    </div>
                    <div className="text-xs text-text-3">
                      {item.kind}
                      {credentialLabel(item) !== null && item.variableName !== null && (
                        <span className="font-mono"> · {item.variableName}</span>
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
                  <TableCell>
                    <CredentialStatusBadge status={credentialStatus(item)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {!refused && !loadingEmpty && !emptyLedger && (
        <Pagination>
          <PaginationPrevious disabled={!hasPreviousPage || loadingPage} onClick={onPreviousPage} />
          <PaginationStatus>
            {items.length === 0
              ? `${String(total)} in all`
              : `${String(pageStart)}–${String(pageStart + items.length - 1)} of ${String(total)}`}
          </PaginationStatus>
          <PaginationNext
            disabled={!hasNextPage || loadingPage}
            loading={loadingPage}
            onClick={onNextPage}
          />
        </Pagination>
      )}
    </Card>
  );
}
