'use client';

// A searchable, filterable, sortable and paged table of inventory rows. With a
// `type` every row is that type: the columns are that type's own and the pills
// filter by status. Without one (a harness's mixed list) a status dropdown and
// per-type pills filter instead.
import type { AssetType, Flag } from '@akasecurity/schema';
import {
  cn,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  SegmentedControl,
  SegmentedControlItem,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { type ReactNode, useMemo, useState } from 'react';

import { SearchField } from '../shared/SearchField.tsx';
import { FlagChip, TrustPill } from './chips.tsx';
import { type Column, MIXED_COLUMNS, NAME_COLUMN, TYPE_COLUMNS } from './columns.ts';
import {
  assetTile,
  GROUPS,
  inlineLabel,
  type InventoryRow,
  isProjectRow,
  needsAttention,
  rowType,
  STATUS,
  STATUS_ORDER,
  type StatusKey,
  statusKeys,
  typeMeta,
} from './data.ts';
import { Ico } from './Ico.tsx';

export const PAGE_SIZE = 25;

type StatusFilter = 'all' | 'attention' | 'ok' | StatusKey;

interface Sort {
  key: string;
  dir: 1 | -1;
}

export interface InventoryTableProps {
  title: string;
  subtitle: string;
  /** The header's leading mark: a harness lettermark or a type tile. */
  avatar: ReactNode;
  rows: InventoryRow[];
  /** The type every row has; null for a harness's mixed list. */
  type: AssetType | null;
  /** Accessible name and placeholder noun for the search field, e.g. "inventory". */
  searchNoun: string;
  onOpen: (row: InventoryRow) => void;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
  /** Rendered between the header and the filters. */
  children?: ReactNode;
}

function matchesStatus(row: InventoryRow, status: StatusFilter): boolean {
  if (status === 'all') return true;
  if (status === 'attention') return needsAttention(row);
  if (status === 'ok') return !needsAttention(row);
  return statusKeys(row).includes(status);
}

const isTrustKey = (k: StatusKey): k is 'unapproved' | 'risky' =>
  k === 'unapproved' || k === 'risky';

function compareValues(a: string | number | null, b: string | number | null): number {
  if (a === null || a === '') return b === null || b === '' ? 0 : 1;
  if (b === null || b === '') return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b));
}

/** The text a cell shows: its display form when the column has one, else its value. */
function cellText(column: Column, row: InventoryRow, renderedAt: number): string {
  const value = column.value(row);
  if (value === null || value === '') return '—';
  return column.display ? column.display(row, renderedAt) || '—' : String(value);
}

/** The status dropdown's label for a filter, as both its option and its trigger read. */
function statusLabel(
  status: StatusFilter,
  reasons: { key: StatusKey; count: number }[],
  attention: number,
  total: number,
): string {
  if (status === 'all') return 'All statuses';
  if (status === 'attention') return `Needs attention (${String(attention)})`;
  if (status === 'ok') return `OK (${String(total - attention)})`;
  const count = reasons.find((r) => r.key === status)?.count ?? 0;
  return `${STATUS[status].short} (${String(count)})`;
}

/** Count rows per status key, in severity order, keeping only keys that occur. */
function statusCounts(rows: InventoryRow[]): { key: StatusKey; count: number }[] {
  const counts = new Map<StatusKey, number>();
  for (const row of rows) {
    for (const k of statusKeys(row)) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return STATUS_ORDER.filter((k) => counts.has(k)).map((k) => ({
    key: k,
    count: counts.get(k) ?? 0,
  }));
}

export function InventoryTable({
  title,
  subtitle,
  avatar,
  rows,
  type,
  searchNoun,
  onOpen,
  renderedAt,
  children,
}: InventoryTableProps) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [typeFilter, setTypeFilter] = useState<AssetType | null>(null);
  const [sort, setSort] = useState<Sort | null>(null);
  const [page, setPage] = useState(0);

  const columns = type === null ? MIXED_COLUMNS : TYPE_COLUMNS[type];
  const sortable = useMemo<Column[]>(
    () => [type === 'hook' ? { ...NAME_COLUMN, label: 'Command' } : NAME_COLUMN, ...columns],
    [type, columns],
  );

  // A filter stays listed while it is active, even once the rows no longer
  // contain it, so the control that clears it never disappears from under it.
  const reasons = useMemo(() => {
    const counts = statusCounts(rows);
    if (status === 'all' || status === 'attention' || status === 'ok') return counts;
    if (counts.some((r) => r.key === status)) return counts;
    return STATUS_ORDER.filter((k) => k === status || counts.some((r) => r.key === k)).map((k) => ({
      key: k,
      count: counts.find((r) => r.key === k)?.count ?? 0,
    }));
  }, [rows, status]);
  const attention = useMemo(() => rows.filter(needsAttention).length, [rows]);
  const okCount = rows.length - attention;
  const typeCounts = useMemo(
    () =>
      type !== null
        ? []
        : GROUPS.map((g) => ({
            meta: g,
            count: rows.filter((r) => rowType(r) === g.type).length,
          })).filter((t) => t.count > 0 || t.meta.type === typeFilter),
    [rows, type, typeFilter],
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let out = rows.filter((row) => {
      if (typeFilter !== null && rowType(row) !== typeFilter) return false;
      if (!matchesStatus(row, status)) return false;
      if (!needle) return true;
      const haystack = [
        row.name,
        isProjectRow(row) ? row.repo : row.sub,
        ...columns.map((c) => cellText(c, row, renderedAt)),
      ];
      return haystack.some((v) => v.toLowerCase().includes(needle));
    });
    if (sort) {
      const column = sortable.find((c) => c.key === sort.key);
      if (column) {
        out = [...out].sort((a, b) => compareValues(column.value(a), column.value(b)) * sort.dir);
      }
    }
    return out;
  }, [rows, query, status, typeFilter, sort, columns, sortable, renderedAt]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages - 1);
  const view = filtered.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE);
  const first = filtered.length === 0 ? 0 : current * PAGE_SIZE + 1;
  const last = Math.min(filtered.length, (current + 1) * PAGE_SIZE);

  const label = (s: StatusFilter) => statusLabel(s, reasons, attention, rows.length);
  const search = (q: string) => {
    setQuery(q);
    setPage(0);
  };
  const toggleSort = (key: string) => {
    setSort((s) => (s?.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));
    setPage(0);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-3.5 border-b border-border px-5 py-4">
        {avatar}
        <div className="min-w-40 flex-1">
          <div className="font-display text-base font-semibold">{title}</div>
          <div className="mt-px text-xs text-text-3">{subtitle}</div>
        </div>
        <SearchField
          value={query}
          onValueChange={search}
          label={`Search ${searchNoun}`}
          placeholder={`Search ${searchNoun}…`}
          surface="card"
          className="h-9 w-full max-w-80 sm:w-72"
        />
      </div>

      {children}

      <div className="flex flex-wrap items-center gap-2 border-b border-border px-5 py-3">
        {type === null ? (
          <>
            <Select
              value={status}
              onValueChange={(v) => {
                setStatus(v as StatusFilter);
                setPage(0);
              }}
            >
              <SelectTrigger
                aria-label="Filter by status"
                className={cn('h-8 w-auto min-w-44 gap-2', status !== 'all' && 'text-primary')}
              >
                <Ico name="flag" className="size-3.5 text-text-3" />
                <SelectValue>{label(status)}</SelectValue>
              </SelectTrigger>
              <SelectContent className="min-w-56">
                <SelectItem value="all">{label('all')}</SelectItem>
                <SelectItem value="attention">{label('attention')}</SelectItem>
                {reasons.length > 0 && (
                  <SelectGroup>
                    <SelectLabel>Reason</SelectLabel>
                    {reasons.map((r) => (
                      <SelectItem key={r.key} value={r.key}>
                        {label(r.key)}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                )}
                <SelectSeparator />
                <SelectItem value="ok">{label('ok')}</SelectItem>
              </SelectContent>
            </Select>
            {typeCounts.length > 0 && <span aria-hidden className="mx-0.5 h-5 w-px bg-border" />}
            <SegmentedControl
              className="flex flex-wrap gap-1.5 border-0 bg-transparent p-0"
              value={typeFilter ?? ''}
              onValueChange={(v) => {
                setTypeFilter(v === '' ? null : (v as AssetType));
                setPage(0);
              }}
            >
              {typeCounts.map((t) => (
                <Pill key={t.meta.type} value={t.meta.type} label={t.meta.label} count={t.count} />
              ))}
            </SegmentedControl>
          </>
        ) : (
          <SegmentedControl
            className="flex flex-wrap gap-1.5 border-0 bg-transparent p-0"
            value={status}
            onValueChange={(v) => {
              if (!v) return;
              setStatus(v as StatusFilter);
              setPage(0);
            }}
          >
            <Pill value="all" label="All" count={rows.length} />
            {reasons.map((r) => (
              <Pill key={r.key} value={r.key} label={STATUS[r.key].short} count={r.count} />
            ))}
            {(okCount > 0 || status === 'ok') && <Pill value="ok" label="OK" count={okCount} />}
          </SegmentedControl>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <Table>
          <TableHeader>
            <TableRow>
              {sortable.map((c) => (
                <TableHead
                  key={c.key}
                  aria-sort={
                    sort?.key === c.key ? (sort.dir === 1 ? 'ascending' : 'descending') : undefined
                  }
                  className={cn('pt-3', c.num && 'text-right', c.key === 'name' && 'pl-5')}
                >
                  <button
                    type="button"
                    onClick={() => {
                      toggleSort(c.key);
                    }}
                    className={cn(
                      'inline-flex cursor-pointer items-center gap-1 uppercase hover:text-text-2',
                      sort?.key === c.key && 'text-text-2',
                    )}
                  >
                    {c.label}
                    {sort?.key === c.key && (
                      <Ico name={sort.dir === 1 ? 'arrow-up' : 'arrow-down'} className="size-3" />
                    )}
                  </button>
                </TableHead>
              ))}
              <TableHead className="pr-5 pt-3 text-right">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {view.map((row) => (
              <InventoryTableRow
                key={`${rowType(row)}:${row.id}`}
                row={row}
                columns={columns}
                renderedAt={renderedAt}
                onOpen={onOpen}
              />
            ))}
          </TableBody>
        </Table>
        {view.length === 0 && (
          <div className="px-5 py-7 text-sm text-text-3">
            {rows.length === 0 ? `No ${searchNoun} yet.` : 'Nothing matches this filter.'}
          </div>
        )}
      </div>

      <Pagination className="justify-start gap-3 border-t border-border px-5 py-3">
        <PaginationStatus className="flex-1">
          {filtered.length === 0
            ? '0 of 0'
            : `${String(first)}–${String(last)} of ${String(filtered.length)}`}
        </PaginationStatus>
        <PaginationPrevious
          disabled={current === 0}
          onClick={() => {
            setPage(current - 1);
          }}
        />
        <span className="text-xs text-text-2">{`Page ${String(current + 1)} of ${String(pages)}`}</span>
        <PaginationNext
          disabled={current >= pages - 1}
          onClick={() => {
            setPage(current + 1);
          }}
        />
      </Pagination>
    </div>
  );
}

function Pill({ value, label, count }: { value: string; label: string; count: number }) {
  return (
    <SegmentedControlItem
      value={value}
      className={cn(
        'flex-none rounded-full border border-border bg-surface px-3 py-1 text-text-2',
        'data-[state=on]:border-primary data-[state=on]:bg-primary-tint data-[state=on]:text-primary data-[state=on]:shadow-none',
      )}
    >
      {label}
      <span className="tabular-nums opacity-70">{count}</span>
    </SegmentedControlItem>
  );
}

function InventoryTableRow({
  row,
  columns,
  renderedAt,
  onOpen,
}: {
  row: InventoryRow;
  columns: Column[];
  renderedAt: number;
  onOpen: (row: InventoryRow) => void;
}) {
  const type = rowType(row);
  const tile = assetTile(type);
  const keys = statusKeys(row);
  const trustKey = keys.find(isTrustKey);
  const flagKeys = keys.filter((k): k is Flag => !isTrustKey(k));
  return (
    <TableRow
      aria-label={`Open ${inlineLabel(typeMeta(type).one)} ${row.name}`}
      onClick={() => {
        onOpen(row);
      }}
      className="cursor-pointer hover:bg-surface-2"
    >
      <TableCell className="pl-5">
        <div className="flex min-w-0 items-center gap-2.5">
          <span
            className={cn('grid size-6.5 shrink-0 place-items-center rounded-md', tile.bg, tile.fg)}
          >
            <Ico name={tile.icon} className="size-3.5" />
          </span>
          <span
            className="max-w-64 truncate font-mono text-xs font-semibold text-text"
            title={row.name}
          >
            {row.name}
          </span>
        </div>
      </TableCell>
      {columns.map((c) => {
        const text = cellText(c, row, renderedAt);
        return (
          <TableCell
            key={c.key}
            className={cn(
              'truncate text-xs text-text-2',
              c.wide ? 'max-w-64' : 'max-w-44',
              c.mono && 'font-mono',
              c.num && 'text-right tabular-nums',
            )}
            title={text}
          >
            {text}
          </TableCell>
        );
      })}
      <TableCell className="pr-5 text-right">
        {keys.length === 0 ? (
          <span className="inline-flex items-center justify-end gap-1.5 text-xs font-semibold text-ok-ink">
            <Ico name="check-circle" className="size-4" />
            <span className="sr-only">OK</span>
          </span>
        ) : (
          <span className="inline-flex flex-wrap items-center justify-end gap-1.5">
            {trustKey && <TrustPill value={trustKey} />}
            {flagKeys.map((k) => (
              <FlagChip key={k} flag={k} mini />
            ))}
          </span>
        )}
      </TableCell>
    </TableRow>
  );
}
