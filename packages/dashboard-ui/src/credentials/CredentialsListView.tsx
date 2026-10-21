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
import type { CredentialListItem } from './types.ts';

/** The status chips the list filters by. */
export type CredentialChip = 'all' | 'ok';

export interface CredentialsListViewProps {
  items: CredentialListItem[];
  /** Credentials matching the search across every page. */
  total: number;
  search: string;
  onSearch: (value: string) => void;
  chip: CredentialChip;
  onChip: (chip: CredentialChip) => void;
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
  /** Shown in place of the table when the host cannot read the list. */
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
  search,
  onSearch,
  chip,
  onChip,
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
  return (
    <Card className="flex flex-col gap-4 p-4 shadow-sm">
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-sev-high-fill text-sev-high-ink">
          <Ico name="key" className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="font-display text-sm font-semibold text-text">Credentials</div>
          <div className="text-xs text-text-3">
            {isLoading ? '…' : `${String(total)} ${total === 1 ? 'credential' : 'credentials'}`}
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
        <Button variant="outline" size="sm" disabled={exporting} onClick={onExport}>
          Export
        </Button>
      </div>

      <div role="group" aria-label="Status" className="flex gap-1.5">
        {(
          [
            ['all', 'All'],
            ['ok', 'OK'],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-pressed={chip === value}
            onClick={() => {
              onChip(value);
            }}
            className={cn(
              'rounded-full border px-3 py-1 text-xs font-semibold',
              chip === value
                ? 'border-primary bg-primary-tint text-primary'
                : 'border-border text-text-2 hover:bg-surface-2',
            )}
          >
            {label} <span className="opacity-65">{isLoading ? '' : String(total)}</span>
          </button>
        ))}
      </div>

      {error !== undefined ? (
        <p role="alert" className="py-10 text-center text-sm text-text-3">
          {error}
        </p>
      ) : !isLoading && items.length === 0 ? (
        <p className="py-10 text-center text-sm text-text-3">
          {search.trim() === ''
            ? 'No credentials have been seen yet. They appear here once an attached machine shares a sighting.'
            : 'Nothing matches this search.'}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {COLUMNS.map((column) => (
                  <TableHead
                    key={column}
                    className={cn(
                      NUMERIC.has(column) && 'text-right',
                      column === 'Status' && 'text-right',
                    )}
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
                  className="cursor-pointer"
                  aria-label={`View credential ${item.variableName ?? item.kind}`}
                  onClick={() => {
                    onSelect(item.id);
                  }}
                >
                  <TableCell>
                    <div className="font-mono text-xs font-semibold text-text">
                      {item.variableName ?? 'Unnamed'}
                    </div>
                    <div className="text-xs text-text-3">{item.kind}</div>
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
                  <TableCell className="text-right">
                    <span className="inline-flex items-center gap-1 text-xs font-semibold text-ok-ink">
                      <Ico name="check-circle" className="size-3.5" /> OK
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {error === undefined && items.length > 0 && (
        <Pagination>
          <PaginationPrevious disabled={!hasPreviousPage || loadingPage} onClick={onPreviousPage} />
          <PaginationStatus>
            {`${String(pageStart)}–${String(pageStart + items.length - 1)} of ${String(total)}`}
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
