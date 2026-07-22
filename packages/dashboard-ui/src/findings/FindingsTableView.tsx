'use client';

import type { FindingGroup, FindingInstance, FindingStatus } from '@akasecurity/schema';
import {
  Badge,
  Button,
  cn,
  SeverityBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { Fragment, type ReactNode, useState } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { ChevronRightIcon, KeyIcon } from '../shared/icons.tsx';
import { ActionTag, AggregateActionTag } from './ActionTag.tsx';
import {
  CATEGORY_ICON_FALLBACK,
  categoryStyle,
  filterGroupsByStatus,
  filterInstancesByStatus,
  FINDING_STATUS_META,
  type FindingColumn,
  instanceLocationLabel,
  type Selection,
  STATUS_FILTER_OPTIONS,
} from './meta.ts';
import { ProviderChips, ProviderTag } from './ProviderChips.tsx';

/**
 * The findings table — grouped rows that expand to per-location instance rows.
 * Fully presentational: selection/expansion state is owned by the caller and
 * flows in as props. Loading/empty/error and the "showing first N" affordance
 * are rendered here so the page stays a thin composition.
 */
export function FindingsTableView({
  groups,
  columns,
  selection,
  expandedIds,
  onToggleExpand,
  onSelectGroup,
  onSelectInstance,
  hasMore = false,
  isLoading = false,
  error = null,
  emptyState,
  sessionFirings,
}: {
  groups: FindingGroup[];
  /** Visible columns, in display order (caller applies column visibility). */
  columns: FindingColumn[];
  selection: Selection | null;
  expandedIds: ReadonlySet<string>;
  onToggleExpand: (groupId: string) => void;
  onSelectGroup: (group: FindingGroup) => void;
  onSelectInstance: (group: FindingGroup, instance: FindingInstance) => void;
  hasMore?: boolean;
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
}) {
  // Lifecycle-status filter — local to the table (not part of the shared
  // severity/type/provider/action FindingsFilters, which round-trip through
  // the app's server query). Narrows the already-fetched `groups` page
  // client-side; 'all' is a no-op (see filterGroupsByStatus).
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const visibleGroups = filterGroupsByStatus(groups, statusFilter);

  return (
    <div className="rounded-xl border border-border bg-surface p-4 shadow-sm">
      <div className="mb-3 flex items-center justify-end gap-2">
        <label htmlFor="findings-status-filter" className="text-xs font-medium text-text-3">
          Status
        </label>
        <select
          id="findings-status-filter"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value as FindingStatus | 'all');
          }}
          className="h-8 rounded-lg border border-border bg-surface px-2 text-sm text-text-2 focus:border-primary focus:outline-none"
        >
          {STATUS_FILTER_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      {error ? (
        <p className="py-8 text-center text-sm text-sev-critical">
          Error loading findings: {error}
        </p>
      ) : isLoading ? (
        <p className="py-8 text-center text-sm text-text-3">Loading findings…</p>
      ) : visibleGroups.length === 0 ? (
        // A local status filter narrows only the fetched page, so "nothing here"
        // can mean "none on this page" rather than "none exist" (grouped rows are
        // server-capped) — say so, instead of the caller's store-empty copy.
        statusFilter !== 'all' ? (
          <p className="py-8 text-center text-sm text-text-3">
            No {FINDING_STATUS_META[statusFilter].label.toLowerCase()} findings on this page
            {hasMore ? ' — more results may exist beyond the fetched limit.' : '.'}
          </p>
        ) : (
          (emptyState ?? (
            <p className="py-8 text-center text-sm text-text-3">No findings match these filters.</p>
          ))
        )
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10" />
              {columns.map((col) => (
                <TableHead key={col.id}>{col.header}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleGroups.map((group) => {
              const expanded = expandedIds.has(group.id);
              const isGroupSelected = selection?.finding.id === group.id && !selection.instance;
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
                      <TableCell key={col.id}>{GROUP_CELL[col.id](group)}</TableCell>
                    ))}
                  </TableRow>
                  {expanded &&
                    filterInstancesByStatus(group.instances, statusFilter).map((instance) => (
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
                          <TableCell key={col.id}>
                            {INSTANCE_CELL[col.id](group, instance)}
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
                  {/* `instances` is the newest slice of a large group, not all
                      of it — say so rather than ending the rows silently. */}
                  {expanded && group.instances.length < group.instanceCount && (
                    <TableRow className="bg-surface-2/50 hover:bg-surface-2/50">
                      <TableCell />
                      <TableCell colSpan={columns.length} className="text-xs text-text-3">
                        Showing the {group.instances.length} most recent of {group.instanceCount}{' '}
                        locations.
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              );
            })}
          </TableBody>
        </Table>
      )}

      {/* The "first N" hint describes the server's fetched-page cap over `groups`;
          it's incoherent alongside the local status filter (which narrows to
          `visibleGroups`), so it only counts the unfiltered page. A non-empty
          filtered result still needs the SAME "more may exist beyond the fetched
          page" caveat as the filtered empty-state above — the local filter only
          ever narrows what was already fetched, so a page that hit the server
          cap can under-represent a status's true count even when some matches
          are visible. */}
      {hasMore &&
        (statusFilter === 'all' ? (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing the first {groups.length} findings — refine the filters to narrow results.
          </p>
        ) : (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing {visibleGroups.length} {FINDING_STATUS_META[statusFilter].label.toLowerCase()}{' '}
            findings from the first {groups.length} fetched — more may exist beyond the fetched
            limit.
          </p>
        ))}
    </div>
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
        <span className="font-semibold text-text">{finding.subtype}</span>
        <span
          className="block max-w-[20rem] truncate font-mono text-xs text-text-3"
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
  const meta = FINDING_STATUS_META[status];
  return (
    <Badge variant={meta.badge} className="h-6">
      {meta.label}
    </Badge>
  );
}

/** Per-column renderers for a group row, keyed by column id. */
const GROUP_CELL: Record<FindingColumn['id'], (g: FindingGroup) => ReactNode> = {
  severity: (g) => <SeverityBadge severity={g.severity} />,
  subtype: (g) => <TypeCell finding={g} />,
  sources: (g) => <ProviderChips ids={g.providers} />,
  locations: (g) => <span className="text-text-3">{g.instanceCount} locations</span>,
  action: (g) => <AggregateActionTag aggregateAction={g.aggregateAction} />,
  status: (g) => <StatusCell status={g.status} />,
  latest: (g) => <span className="text-text-3 text-xs">{relativeTime(g.latestDetectedAt)}</span>,
};

/** Per-column renderers for an instance (sub-)row, keyed by column id. */
const INSTANCE_CELL: Record<
  FindingColumn['id'],
  (g: FindingGroup, i: FindingInstance) => ReactNode
> = {
  severity: (g) => <SeverityBadge severity={g.severity} />,
  subtype: (_g, i) => (
    <div className="flex items-center gap-2.5 pl-1">
      <span className="-mt-1.5 size-3.5 shrink-0 rounded-bl border-b-[1.5px] border-l-[1.5px] border-border-strong" />
      <div className="flex flex-col gap-px">
        <span className="font-semibold text-text text-ui">{i.repo}</span>
        <span className="font-mono text-label text-text-3">{i.id}</span>
      </div>
    </div>
  ),
  sources: (_g, i) => <ProviderTag provider={i.provider} />,
  locations: (_g, i) => (
    <span
      className="font-mono text-xs text-text-3 block max-w-[20rem] truncate"
      title={instanceLocationLabel(i)}
    >
      {instanceLocationLabel(i)}
    </span>
  ),
  action: (_g, i) => <ActionTag action={i.action} />,
  status: (_g, i) => <StatusCell status={i.status} />,
  latest: (_g, i) => <span className="text-text-3 text-xs">{relativeTime(i.detectedAt)}</span>,
};
