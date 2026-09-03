'use client';

import type { FindingGroup, FindingInstance, FindingStatus } from '@akasecurity/schema';
import {
  Badge,
  Button,
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
import { Fragment, type ReactNode } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { ChevronRightIcon, KeyIcon } from '../shared/icons.tsx';
import { ActionTag, AggregateActionTag } from './ActionTag.tsx';
import {
  CATEGORY_ICON_FALLBACK,
  categoryStyle,
  filterInstancesByStatus,
  type FindingColumn,
  findingStatusMeta,
  instanceLocationLabel,
  type Selection,
} from './meta.ts';
import { ProviderChips, ProviderTag } from './ProviderChips.tsx';
import { UserCell, UsersCell } from './UserCell.tsx';

const FINDING_COLUMN_CLASS: Record<FindingColumn['id'], string> = {
  severity: 'min-w-[110px] whitespace-nowrap',
  subtype: '',
  sources: 'min-w-[140px] whitespace-nowrap',
  user: 'min-w-[140px]',
  locations: '',
  action: 'min-w-[130px] whitespace-nowrap',
  status: 'min-w-[110px] whitespace-nowrap',
  latest: 'min-w-[100px] whitespace-nowrap',
};

/**
 * The findings table — grouped rows that expand to per-location instance rows.
 * Fully presentational: selection/expansion state is owned by the caller and
 * flows in as props. Loading/empty/error and the "showing first N" affordance
 * are rendered here so the page stays a thin composition.
 *
 * Layout contract: the card fills its container's height and scrolls the rows
 * internally, so the caller must mount it in a height-constrained parent (an
 * unbroken h-full/min-h-0 chain) — without one the card has no height to fill.
 */
export function FindingsTableView({
  groups,
  columns,
  selection,
  expandedIds,
  onToggleExpand,
  onSelectGroup,
  onSelectInstance,
  hasNextPage = false,
  hasPreviousPage = false,
  onNextPage,
  onPreviousPage,
  loadingNextPage = false,
  pageStart,
  total,
  isLoading = false,
  error = null,
  emptyState,
  sessionFirings,
  statusFilter,
  renderedAt,
}: {
  groups: FindingGroup[];
  /** Visible columns, in display order (caller applies column visibility). */
  columns: FindingColumn[];
  selection: Selection | null;
  expandedIds: ReadonlySet<string>;
  onToggleExpand: (groupId: string) => void;
  onSelectGroup: (group: FindingGroup) => void;
  onSelectInstance: (group: FindingGroup, instance: FindingInstance) => void;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
  /**
   * Advance to the next page. Absent ⇒ the caller cannot paginate, and the
   * truncation notice below is shown instead — which is the honest thing to
   * render when there is more data and no way to reach it.
   */
  onNextPage?: (() => void) | undefined;
  onPreviousPage?: (() => void) | undefined;
  loadingNextPage?: boolean;
  /** 1-indexed position of `groups[0]` within the whole result set — needed to render "51–100 of N". Absent ⇒ falls back to "{groups.length} shown". */
  pageStart?: number | undefined;
  /** Groups matching the filters across the whole scope, not just this page. */
  total?: number | undefined;
  isLoading?: boolean;
  error?: string | null;
  /**
   * Shown instead of the default "No findings match these filters." copy when
   * `groups` is empty — lets a caller distinguish an empty store (onboarding
   * hint) from an empty filter result. Absent ⇒ the default message.
   */
  emptyState?: ReactNode;
  /**
   * Per-rule transcript firing counts for the session the list is scoped to
   * (ruleId → firings). When present, each expanded group states how its
   * deduplicated rows relate to the session's per-firing tally. Absent on
   * unscoped lists.
   */
  sessionFirings?: Record<string, number>;
  /**
   * The statuses the caller's Status filter selected (empty/absent ⇒ no status
   * filter). The store already dropped every non-matching group and pre-narrows
   * each group's instance preview; this re-applies the same narrowing for
   * callers that don't, and drives the explicit notice when a kept group's
   * preview holds no matching instance (every match can be older than the
   * preview window).
   */
  statusFilter?: readonly string[];
  /**
   * The instant this render is measured against, in epoch milliseconds. The host
   * captures one and every relative label below reads it. Required: a view that
   * picks its own instant renders one string while the server renders it and
   * another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
}) {
  return (
    <Card className="flex flex-col overflow-hidden shadow-sm h-full">
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {error ? (
          <p className="py-8 text-center text-sm text-sev-critical-ink">
            Error loading findings: {error}
          </p>
        ) : isLoading ? (
          <p className="py-8 text-center text-sm text-text-3">Loading findings…</p>
        ) : groups.length === 0 ? (
          (emptyState ?? (
            <p className="py-8 text-center text-sm text-text-3">No findings match these filters.</p>
          ))
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10" />
                {columns.map((col) => (
                  <TableHead
                    key={col.id}
                    className={FINDING_COLUMN_CLASS[col.id]}
                    {...(col.title === undefined ? {} : { title: col.title })}
                  >
                    {col.header}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map((group) => {
                const expanded = expandedIds.has(group.id);
                const isGroupSelected = selection?.finding.id === group.id && !selection.instance;
                const visibleInstances = filterInstancesByStatus(group.instances, statusFilter);
                return (
                  <Fragment key={group.id}>
                    <TableRow
                      onClick={() => {
                        onSelectGroup(group);
                      }}
                      aria-label={`View details for ${group.subtype} finding`}
                      className={cn(
                        'cursor-pointer hover:bg-surface-2',
                        isGroupSelected && 'bg-surface-2',
                      )}
                    >
                      <TableCell className="text-text-3">
                        <Button
                          aria-label={expanded ? 'Collapse' : 'Expand'}
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleExpand(group.id);
                          }}
                          size="icon"
                          variant="ghost"
                        >
                          <ChevronRightIcon
                            className={cn('size-4 transition-transform', expanded && 'rotate-90')}
                          />
                        </Button>
                      </TableCell>
                      {columns.map((col) => (
                        <TableCell key={col.id} className={FINDING_COLUMN_CLASS[col.id]}>
                          {GROUP_CELL[col.id](group, renderedAt)}
                        </TableCell>
                      ))}
                    </TableRow>
                    {expanded &&
                      visibleInstances.map((instance) => (
                        <TableRow
                          key={instance.id}
                          onClick={() => {
                            onSelectInstance(group, instance);
                          }}
                          aria-label={`View details for ${group.subtype} finding in ${instance.repo}`}
                          className={cn(
                            'cursor-pointer hover:bg-surface-2',
                            selection?.instance?.id === instance.id
                              ? 'bg-surface-2'
                              : 'bg-surface-2/50',
                          )}
                        >
                          <TableCell />
                          {columns.map((col) => (
                            <TableCell key={col.id} className={FINDING_COLUMN_CLASS[col.id]}>
                              {INSTANCE_CELL[col.id](group, instance, renderedAt)}
                            </TableCell>
                          ))}
                        </TableRow>
                      ))}
                    {/* On a session-scoped list, reconcile this group's deduped
                      rows with the session's per-firing tally — the two counts
                      legitimately differ and the gap confuses otherwise. */}
                    {expanded && sessionFirings && (
                      <TableRow className="bg-surface-2/50 hover:bg-surface-2/50">
                        <TableCell />
                        <TableCell colSpan={columns.length} className="text-xs text-text-3">
                          {(sessionFirings[group.id] ?? 0) > 0
                            ? `Fired ${String(sessionFirings[group.id])} times in this session's transcript — the session's "triggered" tally counts every firing, this row counts unique values.`
                            : `Caught by live enforcement only — not re-detected in this session's transcript.`}
                        </TableCell>
                      </TableRow>
                    )}
                    {/* The group's status folds over EVERY instance while the
                      rows above are only the newest preview — under a status
                      filter every matching instance can sit outside it. Say so
                      rather than expanding to nothing. */}
                    {expanded && visibleInstances.length === 0 && (
                      <TableRow className="bg-surface-2/50 hover:bg-surface-2/50">
                        <TableCell />
                        <TableCell colSpan={columns.length} className="text-xs text-text-3">
                          No locations with the selected status among the most recently detected —
                          the status column reflects all {group.instanceCount} locations.
                        </TableCell>
                      </TableRow>
                    )}
                    {/* `instances` is the newest slice of a large group, not all
                      of it — say so rather than ending the rows silently. */}
                    {expanded &&
                      visibleInstances.length > 0 &&
                      visibleInstances.length < group.instanceCount && (
                        <TableRow className="bg-surface-2/50 hover:bg-surface-2/50">
                          <TableCell />
                          <TableCell colSpan={columns.length} className="text-xs text-text-3">
                            Showing the {visibleInstances.length} most recent of{' '}
                            {group.instanceCount} locations.
                          </TableCell>
                        </TableRow>
                      )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}

        {/* The unit here is TYPES — the toolbar's findings tally counts
          instances and would disagree with this number. */}
      </div>
      {onNextPage
        ? groups.length > 0 && (
            <Pagination>
              <PaginationPrevious
                disabled={!hasPreviousPage || loadingNextPage}
                onClick={onPreviousPage}
              />
              <PaginationStatus>
                {total === undefined || pageStart === undefined
                  ? `${String(groups.length)} shown`
                  : `${String(pageStart)}–${String(pageStart + groups.length - 1)} of ${String(total)} types`}
              </PaginationStatus>
              <PaginationNext
                disabled={!hasNextPage || loadingNextPage}
                loading={loadingNextPage}
                onClick={onNextPage}
              />
            </Pagination>
          )
        : hasNextPage && (
            <p className="mt-4 text-center text-xs text-text-3">
              Showing the first {groups.length} types — refine the filters to narrow results.
            </p>
          )}
    </Card>
  );
}

/** The Type cell — category icon tile + subtype + masked value. */
function TypeCell({ finding }: { finding: FindingGroup }) {
  const Icon = CATEGORY_ICON_FALLBACK[finding.category] ?? KeyIcon;
  return (
    <div className="flex items-center gap-2.5">
      <span
        className={cn(
          'flex size-7 shrink-0 items-center justify-center rounded-lg',
          categoryStyle(finding.category),
        )}
      >
        <Icon className="size-4" />
      </span>
      <div className="flex flex-col">
        <span className="font-semibold text-text wrap-anywhere">{finding.subtype}</span>
        <span
          className="font-mono text-xs text-text-3 wrap-anywhere"
          title={finding.match.maskedValue}
        >
          {finding.match.maskedValue}
        </span>
      </div>
    </div>
  );
}

/** Status cell — a tinted badge from FINDING_STATUS_META, or a neutral dash for
 * legacy findings that predate the resolution feature (status undefined). */
function StatusCell({ status }: { status: FindingStatus | undefined }) {
  if (!status) return <span className="text-text-3">—</span>;
  const meta = findingStatusMeta(status);
  return (
    <Badge variant={meta.badge} className="h-6">
      {meta.label}
    </Badge>
  );
}

/** Per-column renderers for a group row, keyed by column id. */
const GROUP_CELL: Record<FindingColumn['id'], (g: FindingGroup, renderedAt: number) => ReactNode> =
  {
    severity: (g) => <SeverityBadge severity={g.severity} />,
    subtype: (g) => <TypeCell finding={g} />,
    sources: (g) => <ProviderChips ids={g.providers} />,
    user: (g) => <UsersCell users={g.users} />,
    locations: (g) => <span className="text-text-3">{g.instanceCount} locations</span>,
    action: (g) => <AggregateActionTag aggregateAction={g.aggregateAction} />,
    status: (g) => <StatusCell status={g.status} />,
    latest: (g, renderedAt) => (
      <span className="text-text-3 text-xs">{relativeTime(g.latestDetectedAt, renderedAt)}</span>
    ),
  };

/** Per-column renderers for an instance (sub-)row, keyed by column id. */
const INSTANCE_CELL: Record<
  FindingColumn['id'],
  (g: FindingGroup, i: FindingInstance, renderedAt: number) => ReactNode
> = {
  severity: (g) => <SeverityBadge severity={g.severity} />,
  subtype: (_g, i) => (
    <div className="flex items-center gap-2.5 pl-1">
      <span className="-mt-1.5 size-3.5 shrink-0 rounded-bl border-b-[1.5px] border-l-[1.5px] border-border-strong" />
      <div className="flex flex-col gap-px">
        <span className="font-semibold text-text text-ui wrap-anywhere">{i.repo}</span>
        <span className="font-mono text-label text-text-3 wrap-anywhere">{i.id}</span>
      </div>
    </div>
  ),
  sources: (_g, i) => <ProviderTag provider={i.provider} />,
  user: (_g, i) => <UserCell user={i.user} />,
  locations: (_g, i) => (
    <span className="font-mono text-xs text-text-3 wrap-anywhere">{instanceLocationLabel(i)}</span>
  ),
  action: (_g, i) => <ActionTag action={i.action} />,
  status: (_g, i) => <StatusCell status={i.status} />,
  latest: (_g, i, renderedAt) => (
    <span className="text-text-3 text-xs">{relativeTime(i.detectedAt, renderedAt)}</span>
  ),
};
