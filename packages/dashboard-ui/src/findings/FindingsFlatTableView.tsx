'use client';

import type { FindingInstanceDetail } from '@akasecurity/schema';
import {
  Badge,
  Card,
  cn,
  Pagination,
  PaginationNext,
  PaginationPrevious,
  PaginationStatus,
  SeverityBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { KeyIcon } from '../shared/icons.tsx';
import { ActionTag } from './ActionTag.tsx';
import {
  CATEGORY_ICON_FALLBACK,
  categoryStyle,
  FINDING_STATUS_META,
  instanceLocationLabel,
} from './meta.ts';
import { ProviderTag } from './ProviderChips.tsx';

const FINDING_COLUMN_CLASS: Record<string, string> = {
  severity: 'min-w-[110px] whitespace-nowrap',
  sources: 'min-w-[140px] whitespace-nowrap',
  action: 'min-w-[130px] whitespace-nowrap',
  status: 'min-w-[110px] whitespace-nowrap',
  latest: 'min-w-[100px] whitespace-nowrap',
  location: 'min-w-[200px]',
  type: 'min-w-[200px]',
};

/**
 * The flat findings table — one row per finding, newest first.
 *
 * The sibling of FindingsTableView, which folds by rule. This one answers "what
 * happened most recently" and so has no expansion: every row is already a single
 * location, and the counts it shows are findings rather than types.
 *
 * Fully presentational. Selection and pagination state are the caller's; `items`
 * is only the current page's rows, not everything fetched so far.
 *
 * Layout contract: as with FindingsTableView, the card fills its container and
 * scrolls internally, so it needs a height-constrained parent.
 */
export function FindingsFlatTableView({
  items,
  selectedId,
  onSelect,
  onNextPage,
  onPreviousPage,
  hasNextPage = false,
  hasPreviousPage = false,
  loadingNextPage = false,
  pageStart,
  total,
  isLoading = false,
  emptyState,
}: {
  items: FindingInstanceDetail[];
  /** The row rendered as selected ('' for none). */
  selectedId?: string;
  onSelect: (instance: FindingInstanceDetail) => void;
  /** Absent ⇒ no pagination footer, however the has*Page flags read. */
  onNextPage?: () => void;
  onPreviousPage?: () => void;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  loadingNextPage?: boolean;
  /** 1-indexed position of `items[0]` within the whole result set — needed to render "51–100 of N". Absent ⇒ falls back to "{items.length} shown". */
  pageStart?: number;
  /** Findings matching the filters across the whole scope, not just this page. */
  total?: number;
  isLoading?: boolean;
  emptyState?: ReactNode;
}) {
  return (
    <Card className="flex h-full min-h-0 flex-col overflow-hidden shadow-sm">
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {isLoading ? (
          <div className="flex flex-col gap-2 py-2">
            {Array.from({ length: 8 }, (_, i) => (
              <div key={i} className="h-11 animate-pulse rounded-md bg-surface-3" />
            ))}
          </div>
        ) : items.length === 0 ? (
          (emptyState ?? (
            <p className="py-8 text-center text-sm text-text-3">No findings match these filters.</p>
          ))
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className={FINDING_COLUMN_CLASS.severity}>Severity</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.type}>Type</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.sources}>Source</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.location}>Location</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.action}>Action</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.status}>Status</TableHead>
                <TableHead className={FINDING_COLUMN_CLASS.latest}>Detected</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((instance) => {
                const Icon = CATEGORY_ICON_FALLBACK[instance.category] ?? KeyIcon;
                return (
                  <TableRow
                    key={instance.id}
                    data-state={selectedId === instance.id ? 'selected' : undefined}
                    className="cursor-pointer hover:bg-surface-2"
                    onClick={() => {
                      onSelect(instance);
                    }}
                  >
                    <TableCell className={FINDING_COLUMN_CLASS.severity}>
                      <SeverityBadge severity={instance.severity} />
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.type}>
                      <div className="flex items-center gap-2.5">
                        <span
                          className={cn(
                            'flex size-7 shrink-0 items-center justify-center rounded-lg',
                            categoryStyle(instance.category),
                          )}
                        >
                          <Icon aria-hidden focusable={false} className="size-3.5" />
                        </span>
                        <div className="min-w-0">
                          <div className="text-ui font-semibold text-text break-words [word-break:break-word]">
                            {instance.subtype}
                          </div>
                          <div className="font-mono text-xs text-text-3 break-words [word-break:break-word]">
                            {instance.match.maskedValue}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.sources}>
                      <ProviderTag provider={instance.provider} />
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.location}>
                      <div className="min-w-0">
                        <div className="font-mono text-xs text-text-2 break-words [word-break:break-word]">
                          {instanceLocationLabel(instance)}
                        </div>
                        {instance.repo && (
                          <div className="text-xs text-text-3 break-words [word-break:break-word]">
                            {instance.repo}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.action}>
                      <ActionTag action={instance.action} />
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.status}>
                      {instance.status === undefined ? (
                        <span className="text-text-3">—</span>
                      ) : (
                        <Badge variant={FINDING_STATUS_META[instance.status].badge} className="h-6">
                          {FINDING_STATUS_META[instance.status].label}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.latest}>
                      <span className="text-text-3 text-xs">
                        {relativeTime(instance.detectedAt)}
                      </span>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>
      {onNextPage && items.length > 0 && (hasNextPage || hasPreviousPage) && (
        <Pagination>
          <PaginationPrevious
            disabled={!hasPreviousPage || loadingNextPage}
            onClick={onPreviousPage}
          />
          <PaginationStatus>
            {total === undefined || pageStart === undefined
              ? `${String(items.length)} shown`
              : `${String(pageStart)}–${String(pageStart + items.length - 1)} of ${String(total)} findings`}
          </PaginationStatus>
          <PaginationNext
            disabled={!hasNextPage || loadingNextPage}
            loading={loadingNextPage}
            onClick={onNextPage}
          />
        </Pagination>
      )}
    </Card>
  );
}
