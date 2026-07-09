'use client';
// Left pane: search + harness filter, then sessions grouped by day. Props-driven —
// the app owns the filter state and passes a flat, most-recent-first session list
// (the @akasecurity/schema `ActivitySessionSummary[]`); this view groups by day
// (viewer-local) and derives the row's time/duration labels. Renders its own
// loading / error / empty states so both apps share one behaviour.
import type { ActivitySessionSummary, Harness } from '@akasecurity/schema';
import { cn, Skeleton } from '@akasecurity/ui-kit';

import {
  BranchIcon,
  ClockIcon,
  ListIcon,
  RepoIcon,
  SearchIcon,
  ShieldCheckIcon,
} from '../shared/icons.tsx';
import { Provider } from '../shared/Provider.tsx';
import { WidgetError } from '../shared/widget-state.tsx';
import { Metric, StatusDot } from './atoms.tsx';
import { durationLabel, groupSessionsByDay, startLabel } from './format.ts';
import { HarnessSelect } from './HarnessSelect.tsx';

function SessionRow({
  session,
  selected,
  onSelect,
}: {
  session: ActivitySessionSummary;
  selected: boolean;
  onSelect: () => void;
}) {
  const flagged = session.findings > 0;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={selected ? 'true' : undefined}
      className={cn(
        'relative cursor-pointer block w-full rounded-lg px-3 py-2.5 text-left transition-colors',
        selected ? 'bg-primary-tint' : 'hover:bg-surface-2',
      )}
    >
      <div className="mb-2 flex items-center gap-2.5">
        <Provider id={session.harness} size={26} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-ui font-semibold text-text" title={session.title}>
            {session.title}
          </div>
        </div>
        <StatusDot status={session.status} />
      </div>
      <div className="mb-2 flex items-center gap-1.5 font-mono text-label text-text-3">
        <RepoIcon aria-hidden focusable={false} className="size-3 shrink-0" />
        <span className="min-w-0 max-w-[50%] truncate" title={session.project}>
          {session.project}
        </span>
        <span className="shrink-0 text-border-strong">·</span>
        <BranchIcon aria-hidden focusable={false} className="size-3 shrink-0" />
        <span className="min-w-0 flex-1 truncate" title={session.branches[0]}>
          {session.branches[0]}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="text-xs font-semibold text-text-2">{startLabel(session.startedAt)}</span>
        <Metric icon={ClockIcon}>
          {durationLabel(session.startedAt, session.endedAt, session.status)}
        </Metric>
        <Metric icon={ListIcon}>{session.turns} turns</Metric>
        {flagged && (
          <span className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-semibold text-sev-critical">
            <ShieldCheckIcon aria-hidden focusable={false} className="size-3" />
            {session.findings}
          </span>
        )}
      </div>
    </button>
  );
}

function SkeletonRow() {
  return (
    <div className="rounded-lg px-3 py-2.5">
      <div className="mb-2 flex items-center gap-2.5">
        <Skeleton className="size-6.5 shrink-0 rounded-lg" />
        <Skeleton className="h-4 flex-1" />
      </div>
      <Skeleton className="mb-2 h-3 w-2/3" />
      <Skeleton className="h-3 w-1/2" />
    </div>
  );
}

export function SessionListView({
  sessions,
  selectedId,
  onSelect,
  query,
  onQuery,
  harness,
  onHarness,
  isLoading,
  error,
  hasMore = false,
}: {
  sessions: ActivitySessionSummary[];
  selectedId: string;
  onSelect: (id: string) => void;
  query: string;
  onQuery: (q: string) => void;
  harness: Harness[];
  onHarness: (next: Harness[]) => void;
  isLoading: boolean;
  error: string | null;
  hasMore?: boolean;
}) {
  const days = groupSessionsByDay(sessions);
  const filtersActive = query.trim() !== '' || harness.length > 0;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 border-b border-border p-3">
        <div className="mb-2 flex h-8.5 items-center gap-2 rounded-lg border border-border bg-surface-2 px-2.5">
          <SearchIcon aria-hidden focusable={false} className="size-3.5 shrink-0 text-text-3" />
          <input
            value={query}
            onChange={(e) => {
              onQuery(e.target.value);
            }}
            placeholder="Search sessions & events…"
            aria-label="Search sessions and events"
            className="min-w-0 flex-1 bg-transparent text-sm text-text placeholder:text-text-3 focus:outline-none"
          />
        </div>
        <HarnessSelect value={harness} onChange={onHarness} />
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-2" aria-busy={isLoading}>
        {error ? (
          <div className="p-2">
            <WidgetError message={error} />
          </div>
        ) : isLoading && sessions.length === 0 ? (
          <div className="flex flex-col gap-1">
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
          </div>
        ) : days.length === 0 ? (
          <div className="py-10 text-center text-sm text-text-3">
            {filtersActive ? 'No sessions match' : 'No sessions recorded yet'}
          </div>
        ) : (
          <>
            {days.map((group) => (
              <div key={group.day} className="mb-1.5">
                <div className="flex items-center gap-2 px-2 pb-1.5 pt-2">
                  <span className="text-label font-semibold uppercase tracking-wider text-text-3">
                    {group.day}
                  </span>
                  <span className="h-px flex-1 bg-text/6" />
                  <span className="text-label text-text-3">{group.items.length}</span>
                </div>
                <div className="flex flex-col gap-1">
                  {group.items.map((session) => (
                    <SessionRow
                      key={session.id}
                      session={session}
                      selected={session.id === selectedId}
                      onSelect={() => {
                        onSelect(session.id);
                      }}
                    />
                  ))}
                </div>
              </div>
            ))}
            {hasMore && (
              <div className="px-2 py-3 text-center text-label text-text-3">
                Showing the most recent {sessions.length} sessions — narrow the range to see more.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
