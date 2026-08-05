'use client';

import type { FindingInstanceDetail } from '@akasecurity/schema';
import {
  Badge,
  Card,
  cn,
  LoadMore,
  LoadMoreButton,
  LoadMoreStatus,
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

/**
 * The flat findings table — one row per finding, newest first.
 *
 * The sibling of FindingsTableView, which folds by rule. This one answers "what
 * happened most recently" and so has no expansion: every row is already a single
 * location, and the counts it shows are findings rather than types.
 *
 * Fully presentational. Selection and pagination state are the caller's; a page
 * of rows arrives already accumulated.
 *
 * Layout contract: as with FindingsTableView, the card fills its container and
 * scrolls internally, so it needs a height-constrained parent.
 */
export function FindingsFlatTableView({
  items,
  selectedId,
  onSelect,
  onLoadMore,
  loadingMore = false,
  hasMore = false,
  total,
  isLoading = false,
  emptyState,
}: {
  items: FindingInstanceDetail[];
  /** The row rendered as selected ('' for none). */
  selectedId?: string;
  onSelect: (instance: FindingInstanceDetail) => void;
  /** Absent ⇒ no pagination footer, however `hasMore` reads. */
  onLoadMore?: () => void;
  loadingMore?: boolean;
  hasMore?: boolean;
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
                <TableHead>Severity</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Detected</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((instance) => {
                const Icon = CATEGORY_ICON_FALLBACK[instance.category] ?? KeyIcon;
                return (
                  <TableRow
                    key={instance.id}
                    data-state={selectedId === instance.id ? 'selected' : undefined}
                    className="cursor-pointer"
                    onClick={() => {
                      onSelect(instance);
                    }}
                  >
                    <TableCell>
                      <SeverityBadge severity={instance.severity} />
                    </TableCell>
                    <TableCell>
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
                          <div className="truncate text-ui font-semibold text-text">
                            {instance.subtype}
                          </div>
                          <div className="truncate font-mono text-xs text-text-3">
                            {instance.match.maskedValue}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <ProviderTag provider={instance.provider} />
                    </TableCell>
                    <TableCell>
                      <div className="min-w-0">
                        <div className="truncate font-mono text-xs text-text-2">
                          {instanceLocationLabel(instance)}
                        </div>
                        {instance.repo && (
                          <div className="truncate text-xs text-text-3">{instance.repo}</div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <ActionTag action={instance.action} />
                    </TableCell>
                    <TableCell>
                      {instance.status === undefined ? (
                        <span className="text-text-3">—</span>
                      ) : (
                        <Badge variant={FINDING_STATUS_META[instance.status].badge} className="h-6">
                          {FINDING_STATUS_META[instance.status].label}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-text-3">
                      {relativeTime(instance.detectedAt)}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}

        {onLoadMore && items.length > 0 && (
          <LoadMore>
            {hasMore && (
              <LoadMoreButton
                loading={loadingMore}
                onClick={() => {
                  onLoadMore();
                }}
              />
            )}
            <LoadMoreStatus>
              {total === undefined
                ? `${String(items.length)} shown`
                : `${String(items.length)} of ${String(total)} findings`}
            </LoadMoreStatus>
          </LoadMore>
        )}
      </div>
    </Card>
  );
}
