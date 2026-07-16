'use client';
// The master list: a search box, filter tabs, and a scrollable list of detection
// rows. Props-driven — the app owns the query/filter/selection state and the data
// fetch. `updatesById` drives the per-row update badges + the amber "Updates" tab;
// a host may derive it from the registry library or from the
// local store's available_packs mirror. Omit it and those simply don't render.
import type { DetectionListItem } from '@akasecurity/schema';
import { Card } from '@akasecurity/ui-kit';

import { ArrowUpIcon, SearchIcon } from '../shared/icons.tsx';
import { OriginBadge, PolicyTag, UpdateBadge } from './atoms.tsx';
import { PLACEHOLDER_POLICY } from './meta.ts';

// The default tab set — "Updates" is fed by the local available_packs mirror
// recorded by the plugin/CLI.
export const DETECTION_FILTER_TABS: readonly [string, string][] = [
  ['all', 'All'],
  ['library', 'Library'],
  ['updates', 'Updates'],
];

function DetectionRow({
  d,
  sel,
  updateVersion,
  onClick,
}: {
  d: DetectionListItem;
  sel: boolean;
  updateVersion?: string | undefined;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        'w-full cursor-pointer rounded-lg px-3 py-2.5 text-left transition-colors ' +
        (sel ? 'bg-primary-tint' : 'hover:bg-surface-2')
      }
    >
      <div className="min-w-0 flex-1 flex flex-col gap-1">
        <div className="flex items-center gap-1.5 justify-between">
          <div className="flex items-center gap-1.5 min-w-0">
            <span
              title={d.enabled ? 'Enabled' : 'Disabled'}
              className={
                'size-2 shrink-0 rounded-full ' +
                (d.enabled ? 'bg-ok ring-3 ring-ok-fill' : 'bg-border-strong')
              }
            />
            <span className="truncate text-sm font-semibold text-text" title={d.name}>
              {d.name}
            </span>
          </div>
          <div className="font-mono text-xs text-text-3">v{d.version}</div>
        </div>
        <div className="flex items-center gap-1.5 justify-between">
          <span className="font-mono text-xs text-text-3">{d.id}</span>
          <span className="text-xs text-text-3 shrink-0">
            {d.ruleCount} rule{d.ruleCount === 1 ? '' : 's'}
          </span>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-1">
          <OriginBadge origin={d.origin} />
          <PolicyTag policy={d.policyId ?? PLACEHOLDER_POLICY} />
          {updateVersion ? <UpdateBadge version={updateVersion} /> : null}
        </div>
      </div>
    </button>
  );
}

export function DetectionsListView({
  items,
  counts,
  activeId,
  query,
  filter,
  onQueryChange,
  onFilterChange,
  onSelect,
  isLoading = false,
  error = null,
  updatesById,
  filterTabs = DETECTION_FILTER_TABS,
}: {
  items: DetectionListItem[];
  counts: Record<string, number>;
  activeId: string;
  query: string;
  filter: string;
  onQueryChange: (q: string) => void;
  onFilterChange: (f: string) => void;
  onSelect: (id: string) => void;
  isLoading?: boolean | undefined;
  error?: string | null | undefined;
  updatesById?: Map<string, string> | undefined;
  filterTabs?: readonly [string, string][] | undefined;
}) {
  return (
    <Card className="flex flex-col overflow-hidden shadow-sm">
      <div className="border-b border-border p-3">
        <div className="relative">
          <SearchIcon
            aria-hidden
            focusable={false}
            className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-3"
          />
          <input
            value={query}
            onChange={(ev) => {
              onQueryChange(ev.target.value);
            }}
            spellCheck={false}
            placeholder="Search detections…"
            className="h-9 w-full rounded-lg border border-border bg-surface-2 pl-9 pr-3 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-none"
          />
        </div>
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          {filterTabs.map(([k, lbl]) => {
            const on = filter === k;
            const n = counts[k] ?? 0;
            const amber = k === 'updates' && n > 0;
            return (
              <button
                key={k}
                type="button"
                onClick={() => {
                  onFilterChange(k);
                }}
                className={
                  'inline-flex h-7 items-center gap-1.5 cursor-pointer rounded-full border px-2.5 text-xs font-semibold ' +
                  (on
                    ? amber
                      ? 'border-sev-high bg-sev-high-fill text-sev-high'
                      : 'border-primary bg-primary-tint text-primary'
                    : amber
                      ? 'border-border text-sev-high'
                      : 'border-border bg-surface text-text-2')
                }
              >
                {amber && <ArrowUpIcon aria-hidden focusable={false} className="size-3" />}
                {lbl}
                <span className="text-label font-bold opacity-70">{n}</span>
              </button>
            );
          })}
        </div>
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto p-3">
        {isLoading ? (
          <div className="grid flex-1 place-items-center p-6 text-center text-xs text-text-3">
            Loading detections…
          </div>
        ) : error ? (
          <div className="grid flex-1 place-items-center p-6 text-center text-xs text-sev-critical">
            {error}
          </div>
        ) : items.length === 0 ? (
          <div className="grid flex-1 place-items-center p-6 text-center text-xs text-text-3">
            {query.trim() ? `No detections match “${query.trim()}”` : 'No detections in this view'}
          </div>
        ) : (
          items.map((d) => (
            <DetectionRow
              key={d.id}
              d={d}
              sel={d.id === activeId}
              updateVersion={updatesById?.get(d.id)}
              onClick={() => {
                onSelect(d.id);
              }}
            />
          ))
        )}
      </div>
    </Card>
  );
}
