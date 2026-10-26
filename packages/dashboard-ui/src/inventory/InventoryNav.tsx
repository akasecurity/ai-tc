'use client';

// Left rail: the attention summary, the By harness / By type switch, and a flat
// list of harnesses or asset types. Picking an entry fills the right-hand table.
import type { AssetGroup, AssetType, HarnessSummary, ProjectSummary } from '@akasecurity/schema';
import { Card, cn, SegmentedControl, SegmentedControlItem } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import { Provider } from '../shared/Provider.tsx';
import { EmptyState } from './chips.tsx';
import { GROUPS, harnessRows, type InventoryView, needsAttention, typeRows } from './data.ts';
import { Ico } from './Ico.tsx';
import type { IconName } from './icons.ts';

/** An entry after the harnesses or asset types that opens a page of its own. */
export interface InventoryNavLink {
  key: string;
  label: string;
  icon: IconName;
  /** Tailwind classes for the icon tile. */
  fg: string;
  bg: string;
  /** null when the count is not known. */
  count: number | null;
  attention: number;
  /** True while the host shows the page this entry opens. */
  selected?: boolean | undefined;
  onSelect: () => void;
}

/** A reason per list, set only for a list the host could not read. */
export interface InventoryNavUnavailable {
  harnesses?: string | undefined;
  assets?: string | undefined;
  projects?: string | undefined;
}

export interface InventoryNavProps {
  harnesses: HarnessSummary[];
  projects: ProjectSummary[];
  assetGroups: AssetGroup[];
  view: InventoryView;
  onView: (view: InventoryView) => void;
  /** The highlighted harness (By harness) — null when there is none. */
  harness: HarnessSummary['id'] | null;
  /** The highlighted type (By type). */
  type: AssetType;
  onSelectHarness: (id: HarnessSummary['id']) => void;
  onSelectType: (type: AssetType) => void;
  /** True while the lists are still loading with nothing cached. */
  isLoading?: boolean | undefined;
  /**
   * Why a list is unavailable, per list — a permission refusal, or a read that
   * failed. The reason is shown in place of that list, nothing is counted from
   * it, and the summary falls back to a lower bound over the lists that are in
   * ("At least N to review"), or "Not available" when none of those needs review.
   */
  unavailable?: InventoryNavUnavailable | undefined;
  /** Entries the host adds after the list, in either view; each counts toward the attention summary. */
  links?: readonly InventoryNavLink[] | undefined;
}

export function InventoryNav({
  harnesses,
  projects,
  assetGroups,
  view,
  onView,
  harness,
  type,
  onSelectHarness,
  onSelectType,
  isLoading,
  unavailable,
  links = [],
}: InventoryNavProps) {
  const loading = isLoading === true;
  // One state per list: a list still out reads as loading, an unavailable one
  // reads as its reason, and only a list that is in produces a count, a total
  // or an empty state.
  const {
    harnesses: harnessesReason,
    assets: assetsReason,
    projects: projectsReason,
  } = unavailable ?? {};
  /** The list a type's rows come from, when that list is unavailable. */
  const typeReason = (t: AssetType) => (t === 'project' ? projectsReason : assetsReason);
  // Every project and asset once, counted the way the tables count them.
  const linkAttention = links.reduce((n, link) => n + link.attention, 0);
  const groupAttention = GROUPS.map((g) => ({
    type: g.type,
    count: typeRows(g.type, projects, assetGroups).filter(needsAttention).length,
    unavailable: typeReason(g.type) !== undefined,
  }));
  const totalIsPartial = groupAttention.some((g) => g.unavailable);
  // What needs review across the lists that are in — the whole total when none
  // is unavailable, a lower bound when one is.
  const knownAttention =
    groupAttention.reduce((n, g) => n + (g.unavailable ? 0 : g.count), 0) + linkAttention;
  const totalReason = [
    ...new Set([projectsReason, assetsReason].filter((r) => r !== undefined)),
  ].join('\n');
  const linkRows = links.map((link) => (
    <NavRow
      key={link.key}
      icon={<TileIcon icon={link.icon} fg={link.fg} bg={link.bg} />}
      label={link.label}
      count={link.count}
      attention={link.attention}
      selected={link.selected ?? false}
      onSelect={link.onSelect}
    />
  ));
  const linkList = linkRows.length > 0 && (
    <ul aria-label="Pages" className="mt-0.5 flex flex-col gap-0.5">
      {linkRows}
    </ul>
  );

  return (
    <Card className="flex w-60 shrink-0 flex-col self-start overflow-hidden shadow-sm">
      <div className="border-b border-border px-4 pb-3.5 pt-4">
        <div className="mb-3 flex items-center gap-2">
          <span className="font-display text-sm font-semibold">All assets</span>
          {loading ? (
            <span className="ml-auto text-xs text-text-3">…</span>
          ) : totalIsPartial ? (
            knownAttention > 0 ? (
              <span
                className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-sev-high-ink"
                title={totalReason}
              >
                <Ico name="flag" className="size-3.5" />
                {`At least ${String(knownAttention)} to review`}
              </span>
            ) : (
              <span className="ml-auto text-xs text-text-3" title={totalReason}>
                Not available
              </span>
            )
          ) : (
            <span
              className={cn(
                'ml-auto inline-flex items-center gap-1.5 text-xs font-semibold',
                knownAttention ? 'text-sev-high-ink' : 'text-ok-ink',
              )}
            >
              <Ico name={knownAttention ? 'flag' : 'check-circle'} className="size-3.5" />
              {knownAttention ? `${String(knownAttention)} to review` : 'All clear'}
            </span>
          )}
        </div>
        <SegmentedControl
          className="flex w-full"
          value={view}
          onValueChange={(v) => {
            if (v) onView(v as InventoryView);
          }}
        >
          <SegmentedControlItem value="harness" className="flex-1">
            <Ico name="layers" /> By harness
          </SegmentedControlItem>
          <SegmentedControlItem value="type" className="flex-1">
            <Ico name="list" /> By type
          </SegmentedControlItem>
        </SegmentedControl>
      </div>

      <nav aria-label="Inventory" className="p-2">
        {view === 'harness' ? (
          harnessesReason !== undefined ? (
            <EmptyState message={harnessesReason} />
          ) : loading && harnesses.length === 0 ? (
            <Loading />
          ) : harnesses.length === 0 ? (
            <EmptyState message="No harnesses detected" />
          ) : (
            <ul aria-label="Harnesses" className="flex flex-col gap-0.5">
              {harnesses.map((h) => {
                const rows = harnessRows(h);
                return (
                  <NavRow
                    key={h.id}
                    icon={<Provider id={h.id} size={26} />}
                    label={h.label}
                    count={rows.length}
                    attention={rows.filter(needsAttention).length}
                    selected={h.id === harness}
                    onSelect={() => {
                      onSelectHarness(h.id);
                    }}
                  />
                );
              })}
            </ul>
          )
        ) : loading && projects.length === 0 && assetGroups.length === 0 ? (
          <Loading />
        ) : (
          <ul aria-label="Asset types" className="flex flex-col gap-0.5">
            {GROUPS.map((g) => {
              const rows = typeRows(g.type, projects, assetGroups);
              const unknown = typeReason(g.type) !== undefined || (loading && rows.length === 0);
              return (
                <NavRow
                  key={g.type}
                  icon={<TileIcon icon={g.icon} fg={g.fg} bg={g.bg} />}
                  label={g.label}
                  count={unknown ? null : rows.length}
                  attention={unknown ? 0 : rows.filter(needsAttention).length}
                  selected={g.type === type}
                  onSelect={() => {
                    onSelectType(g.type);
                  }}
                />
              );
            })}
          </ul>
        )}
        {linkList}
      </nav>
    </Card>
  );
}

function Loading() {
  return (
    <div role="status" className="px-3 py-6 text-center text-xs text-text-3">
      Loading inventory…
    </div>
  );
}

function TileIcon({ icon, fg, bg }: { icon: IconName; fg: string; bg: string }) {
  return (
    <span className={cn('grid size-6.5 shrink-0 place-items-center rounded-md', bg, fg)}>
      <Ico name={icon} className="size-3.5" />
    </span>
  );
}

function NavRow({
  icon,
  label,
  count,
  attention,
  selected,
  onSelect,
}: {
  icon: ReactNode;
  label: string;
  /** null when the count is not known. */
  count: number | null;
  attention: number;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        aria-current={selected ? 'true' : undefined}
        onClick={onSelect}
        className={cn(
          'flex w-full cursor-pointer items-center gap-2.5 rounded-lg px-2.5 py-2 text-left',
          selected ? 'bg-primary-tint' : 'hover:bg-surface-2',
        )}
      >
        {icon}
        <span className="min-w-0 flex-1 truncate text-sm font-semibold text-text" title={label}>
          {label}
        </span>
        {attention > 0 && (
          <span
            role="img"
            aria-label={`${String(attention)} need attention`}
            title={`${String(attention)} need attention`}
            className="size-1.5 shrink-0 rounded-full bg-sev-high"
          />
        )}
        <span className="shrink-0 text-xs tabular-nums text-text-3">{count ?? '—'}</span>
      </button>
    </li>
  );
}
