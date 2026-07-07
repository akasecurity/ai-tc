'use client';
// Left pane: search + harness filter, then sessions grouped by day. Props-driven —
// the app owns the filter state and passes the already-grouped days.
import { cn } from '@akasecurity/ui-kit';

import {
  BranchIcon,
  ClockIcon,
  ListIcon,
  RepoIcon,
  SearchIcon,
  ShieldCheckIcon,
} from '../shared/icons.tsx';
import { Provider } from '../shared/Provider.tsx';
import { Metric, StatusDot } from './atoms.tsx';
import { HarnessSelect } from './HarnessSelect.tsx';
import type { ActivitySession, HarnessId, SessionDay } from './types.ts';

function SessionRow({
  session,
  selected,
  onSelect,
}: {
  session: ActivitySession;
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
        <span className="text-xs font-semibold text-text-2">{session.startLabel}</span>
        <Metric icon={ClockIcon}>{session.duration}</Metric>
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

export function SessionListView({
  days,
  selectedId,
  onSelect,
  query,
  onQuery,
  harness,
  onHarness,
}: {
  days: SessionDay[];
  selectedId: string;
  onSelect: (id: string) => void;
  query: string;
  onQuery: (q: string) => void;
  harness: HarnessId[];
  onHarness: (next: HarnessId[]) => void;
}) {
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
      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {days.length === 0 ? (
          <div className="py-10 text-center text-sm text-text-3">No sessions match</div>
        ) : (
          days.map((group) => (
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
          ))
        )}
      </div>
    </div>
  );
}
