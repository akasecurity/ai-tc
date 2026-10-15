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
   * Set when the host cannot read the harness and asset lists. The reason is shown
   * in their place, and nothing is counted or summarised from the lists it lacks.
   */
  assetsRefusal?: string | undefined;
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
  assetsRefusal,
}: InventoryNavProps) {
  const empty = harnesses.length === 0 && projects.length === 0 && assetGroups.length === 0;
  // Every project and asset once, counted the way the tables count them.
  const attention = GROUPS.reduce(
    (n, g) => n + typeRows(g.type, projects, assetGroups).filter(needsAttention).length,
    0,
  );

  return (
    <Card className="flex w-60 shrink-0 flex-col self-start overflow-hidden shadow-sm">
      <div className="border-b border-border px-4 pb-3.5 pt-4">
        <div className="mb-3 flex items-center gap-2">
          <span className="font-display text-sm font-semibold">All assets</span>
          {isLoading && empty ? (
            <span className="ml-auto text-xs text-text-3">…</span>
          ) : assetsRefusal !== undefined ? (
            <span className="ml-auto text-xs text-text-3" title={assetsRefusal}>
              Not available
            </span>
          ) : (
            <span
              className={cn(
                'ml-auto inline-flex items-center gap-1.5 text-xs font-semibold',
                attention ? 'text-sev-high-ink' : 'text-ok-ink',
              )}
            >
              <Ico name={attention ? 'flag' : 'check-circle'} className="size-3.5" />
              {attention ? `${String(attention)} to review` : 'All clear'}
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

      <nav aria-label={view === 'harness' ? 'Harnesses' : 'Asset types'} className="p-2">
        {isLoading && empty ? (
          <div className="px-3 py-6 text-center text-xs text-text-3">Loading inventory…</div>
        ) : view === 'harness' ? (
          assetsRefusal !== undefined ? (
            <EmptyState message={assetsRefusal} />
          ) : harnesses.length === 0 ? (
            <EmptyState message="No harnesses detected" />
          ) : (
            <ul className="flex flex-col gap-0.5">
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
        ) : (
          <ul className="flex flex-col gap-0.5">
            {GROUPS.map((g) => {
              const rows = typeRows(g.type, projects, assetGroups);
              const unreadable = assetsRefusal !== undefined && g.type !== 'project';
              return (
                <NavRow
                  key={g.type}
                  icon={
                    <span
                      className={cn(
                        'grid size-6.5 shrink-0 place-items-center rounded-md',
                        g.bg,
                        g.fg,
                      )}
                    >
                      <Ico name={g.icon} className="size-3.5" />
                    </span>
                  }
                  label={g.label}
                  count={unreadable ? null : rows.length}
                  attention={unreadable ? 0 : rows.filter(needsAttention).length}
                  selected={g.type === type}
                  onSelect={() => {
                    onSelectType(g.type);
                  }}
                />
              );
            })}
          </ul>
        )}
      </nav>
    </Card>
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
