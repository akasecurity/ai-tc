'use client';

import type { FindingGroup, FindingInstance, FindingStatus } from '@akasecurity/schema';
import {
  Badge,
  Button,
  Card,
  cn,
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
  FINDING_STATUS_META,
  type FindingColumn,
  instanceLocationLabel,
  type Selection,
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
  statusFilter,
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
  /**
   * The statuses the caller's Status filter selected (empty/absent ⇒ no status
   * filter). The store already dropped every group whose status is not among
   * them; this narrows an expanded group's instance rows to match.
   */
  statusFilter?: readonly string[];
}) {
  return (
    <Card className="flex flex-col overflow-hidden shadow-sm h-full">
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        {error ? (
          <p className="py-8 text-center text-sm text-sev-critical px-4">
            Error loading findings: {error}
          </p>
        ) : isLoading ? (
          <p className="py-8 text-center text-sm text-text-3 px-4">Loading findings…</p>
        ) : groups.length === 0 ? (
          (emptyState ?? (
            <p className="py-8 text-center text-sm text-text-3 px-4">
              No findings match these filters.
            </p>
          ))
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
              {groups.map((group) => {
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

        {/* The server's fetched-page cap over the full filtered set. */}
        {hasMore && (
          <p className="mt-4 text-center text-xs text-text-3">
            Showing the first {groups.length} findings — refine the filters to narrow results.
          </p>
        )}
      </div>
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
