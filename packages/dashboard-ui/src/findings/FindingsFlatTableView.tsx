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
  findingStatusMeta,
  instanceLocationLabel,
  USER_COLUMN_TITLE,
} from './meta.ts';
import { ProviderTag } from './ProviderChips.tsx';
import { UserCell } from './UserCell.tsx';

type FlatColumnId =
  'severity' | 'type' | 'sources' | 'user' | 'location' | 'action' | 'status' | 'latest';

const FINDING_COLUMN_CLASS: Record<FlatColumnId, string> = {
  severity: 'min-w-[110px] whitespace-nowrap',
  sources: 'min-w-[140px] whitespace-nowrap',
  user: 'min-w-[140px]',
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
  showUserColumn = false,
  renderedAt,
}: {
  items: FindingInstanceDetail[];
  /** The row rendered as selected ('' for none). */
  selectedId?: string;
  /**
   * Render the User column, which reads each row's `user`. Off by default:
   * only a store that attributes findings to people sets that field, and a
   * single-user store would show a column of dashes.
   */
  showUserColumn?: boolean;
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
  /**
   * The instant this render is measured against, in epoch milliseconds. The host
   * captures one and every relative label below reads it. Required: a view that
   * picks its own instant renders one string while the server renders it and
   * another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
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
                {showUserColumn && (
                  <TableHead className={FINDING_COLUMN_CLASS.user} title={USER_COLUMN_TITLE}>
                    User
                  </TableHead>
                )}
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
                          <div className="text-ui font-semibold text-text wrap-anywhere">
                            {instance.subtype}
                          </div>
                          <div className="font-mono text-xs text-text-3 wrap-anywhere">
                            {instance.match.maskedValue}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.sources}>
                      <ProviderTag provider={instance.provider} />
                    </TableCell>
                    {showUserColumn && (
                      <TableCell className={FINDING_COLUMN_CLASS.user}>
                        <UserCell user={instance.user} />
                      </TableCell>
                    )}
                    <TableCell className={FINDING_COLUMN_CLASS.location}>
                      <div className="min-w-0">
                        <div className="font-mono text-xs text-text-2 wrap-anywhere">
                          {instanceLocationLabel(instance)}
                        </div>
                        {instance.repo && (
                          <div className="text-xs text-text-3 wrap-anywhere">{instance.repo}</div>
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
                        <Badge variant={findingStatusMeta(instance.status).badge} className="h-6">
                          {findingStatusMeta(instance.status).label}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className={FINDING_COLUMN_CLASS.latest}>
                      <span className="text-text-3 text-xs">
                        {relativeTime(instance.detectedAt, renderedAt)}
                      </span>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>
      {onNextPage && items.length > 0 && (
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
