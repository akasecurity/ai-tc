'use client';
import { CredentialStatus } from '@akasecurity/schema';
import {
  Badge,
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
import { credentialLabel, credentialName } from './name.ts';
import { CREDENTIAL_STATUS, credentialStatusLabel } from './status.ts';
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

/** The credential ledger: one row per detected value, newest first. */
export function CredentialsListView({
  items,
  total,
  status: statusProp = null,
  onStatus,
  statusCounts,
  search,
  onSearch,
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

      {onStatus !== undefined && (
        <StatusChips
          status={status}
          onStatus={onStatus}
          counts={refused || isLoading ? undefined : statusCounts}
        />
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
            : status !== null
              ? `No credentials are ${CREDENTIAL_STATUS[status].label.toLowerCase()}${search.trim() === '' ? '.' : ' in this search.'}`
              : search.trim() === ''
                ? 'No credentials have been seen yet. They appear here once an attached machine shares a sighting.'
                : 'Nothing matches this search.'}
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
                    <span className="inline-flex flex-wrap gap-1.5">
                      {item.statuses.map((s) => (
                        <Badge key={s} variant="medium">
                          {credentialStatusLabel(s)}
                        </Badge>
                      ))}
                    </span>
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
    <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-2">
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
            className={cn(
              'inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-full border px-2.5 text-xs font-semibold',
              on
                ? 'border-primary bg-primary-tint text-primary'
                : 'border-border bg-surface text-text-2',
            )}
          >
            {chip.label}
            {chip.count !== undefined && (
              <span className="text-label font-bold opacity-70">{String(chip.count)}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
