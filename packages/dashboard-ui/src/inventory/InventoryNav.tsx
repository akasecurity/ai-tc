'use client';

// Left rail: the unified asset navigator. Two view modes — "By harness" (a tree
// of harnesses → projects then asset categories) and "By type" (grouped
// sections). Header carries the overall attention summary, search and the
// view-mode / type-filter toggles. Fed schema shapes straight from the
// inventory API (HarnessSummary · AssetGroup · ProjectSummary).
import type {
  AssetGroup,
  AssetSummary,
  AssetType,
  Flag,
  HarnessSummary,
  ProjectSummary,
} from '@akasecurity/schema';
import { Badge, Card, cn, SegmentedControl, SegmentedControlItem } from '@akasecurity/ui-kit';
import { useMemo } from 'react';

import { Provider } from '../shared/Provider.tsx';
import { AccessBar, EmptyState, FlagChips, TrustPill, VisBadge } from './chips.tsx';
import {
  ASSET_META,
  assetTile,
  FLAG,
  GROUPS,
  langColor,
  PROJECT_GROUP,
  rollup,
  type Selection,
  TRUST,
  type TypeMeta,
} from './data.ts';
import { Ico } from './Ico.tsx';
import { type IconName } from './icons.ts';

type TypeFilter = 'all' | AssetType;
type AssetsByType = Record<Exclude<AssetType, 'project'>, AssetSummary[]>;

const projFlagItems = (projects: ProjectSummary[]): { flags: Flag[] }[] =>
  projects.map((p) => ({ flags: p.findingsCount > 0 ? (['findings'] as Flag[]) : [] }));

export interface InventoryNavProps {
  projects: ProjectSummary[];
  assetGroups: AssetGroup[];
  harnesses: HarnessSummary[];
  sel: Selection | null;
  viewMode: 'tree' | 'type';
  onViewMode: (m: 'tree' | 'type') => void;
  expanded: Record<string, boolean>;
  onToggleExpand: (id: string, next?: boolean) => void;
  typeFilter: TypeFilter;
  onTypeFilter: (t: TypeFilter) => void;
  query: string;
  onQuery: (q: string) => void;
  // True while the primary lists (harnesses/assets/projects) are still fetching
  // with nothing cached — shows a loading line instead of an empty state.
  isLoading?: boolean | undefined;
  // Store-wide attention count (assets/projects with a flag or finding),
  // provided by the data-fetching wrapper; undefined while it loads.
  attention?: number | undefined;
  // Harness the currently-selected project was opened from (null if opened from
  // the by-type view). Scopes the selected-row highlight to that one harness so
  // a project nested under several harnesses doesn't light up in all of them.
  selFromHarness?: string | null;
  // `fromHarness` records the harness a project was opened from so its detail
  // pane can offer a "back to harness" close; omitted in the by-type view.
  onSelectProject: (id: string, fromHarness?: string) => void;
  // `fromHarness` records the harness an asset was opened from so its detail pane
  // can offer a "back to harness" close; omitted in the by-type view.
  onSelectAsset: (it: AssetSummary, fromHarness?: string) => void;
  onSelectHarness: (id: string) => void;
}

const SEGMENTS: { type: TypeFilter; label: string }[] = [
  { type: 'all', label: 'All' },
  ...GROUPS.map((g) => ({
    type: g.type,
    label: g.label === 'Configuration' ? 'Config' : g.label.replace(' servers', ''),
  })),
];

export function InventoryNav(props: InventoryNavProps) {
  const {
    projects,
    assetGroups,
    harnesses,
    viewMode,
    onViewMode,
    typeFilter,
    onTypeFilter,
    query,
    onQuery,
    attention,
    isLoading,
  } = props;

  // Index the API's grouped assets by type for the by-type view.
  const assetsByType = useMemo<AssetsByType>(() => {
    const map: AssetsByType = { skill: [], mcp: [], hook: [], config: [] };
    for (const g of assetGroups) {
      if (g.type !== 'project') map[g.type] = g.items;
    }
    return map;
  }, [assetGroups]);

  const projList = useMemo(() => {
    const ql = query.toLowerCase();
    const matchq = (s: string) => !ql || s.toLowerCase().includes(ql);
    return projects.filter((p) => matchq(p.name) || matchq(p.repo));
  }, [projects, query]);

  // Store-wide attention count from the data layer. Undefined while it loads —
  // we show a neutral placeholder rather than a client-side re-derivation, which
  // would use a different (and drift-prone) formula than the store's
  // distinct-count attentionCount.
  const attentionLoading = attention === undefined;

  return (
    <Card className="flex w-85 shrink-0 flex-col overflow-hidden shadow-sm">
      {/* header */}
      <div className="border-b border-border px-4 pb-3 pt-4">
        <div className="mb-3 flex items-center gap-2">
          <span className="font-display text-base font-semibold">All assets</span>
          {attentionLoading ? (
            <span className="ml-auto text-xs text-text-3">…</span>
          ) : (
            <span
              className={cn(
                'ml-auto inline-flex items-center gap-1.5 text-xs font-semibold',
                attention ? 'text-sev-high' : 'text-ok',
              )}
            >
              <Ico name={attention ? 'flag' : 'check-circle'} className="size-3.5" />
              {attention ? `${String(attention)} to review` : 'All clear'}
            </span>
          )}
        </div>

        <div className="relative">
          <Ico
            name="search"
            className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-text-3"
          />
          <input
            value={query}
            onChange={(e) => {
              onQuery(e.target.value);
            }}
            placeholder="Search assets…"
            className="h-8.5 w-full rounded-lg border border-border bg-surface-2 pl-9 pr-3 text-sm text-text placeholder:text-text-3 focus:border-primary focus:outline-none"
          />
        </div>

        <SegmentedControl
          className="mt-3 flex w-full"
          value={viewMode}
          onValueChange={(v) => {
            if (v) onViewMode(v as 'tree' | 'type');
          }}
        >
          <SegmentedControlItem value="tree">
            <Ico name="layers" /> By harness
          </SegmentedControlItem>
          <SegmentedControlItem value="type">
            <Ico name="list" /> By type
          </SegmentedControlItem>
        </SegmentedControl>

        {viewMode === 'type' && (
          <SegmentedControl
            className="mt-2.5 flex w-full flex-wrap border-0 bg-transparent p-0 gap-1.5"
            value={typeFilter}
            onValueChange={(v) => {
              if (v) onTypeFilter(v as TypeFilter);
            }}
          >
            {SEGMENTS.map((s) => (
              <SegmentedControlItem
                key={s.type}
                value={s.type}
                className={cn(
                  'flex-none rounded-full border border-border bg-surface px-2.5 py-1 text-text-2',
                  'data-[state=on]:border-transparent data-[state=on]:bg-text data-[state=on]:text-surface data-[state=on]:shadow-none',
                )}
              >
                {s.label}
              </SegmentedControlItem>
            ))}
          </SegmentedControl>
        )}
      </div>

      {/* body */}
      <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2.5 pt-1">
        {isLoading &&
        harnesses.length === 0 &&
        projects.length === 0 &&
        assetGroups.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-text-3">Loading inventory…</div>
        ) : viewMode === 'tree' ? (
          <TreeView {...props} />
        ) : (
          <TypeView {...props} projList={projList} assetsByType={assetsByType} />
        )}
      </div>
    </Card>
  );
}

// ─── Tree view ───────────────────────────────────────────────────────────────
// Each harness expands to its projects first, then the asset categories
// (skills · MCP · hooks · config). Projects nest under the harness that worked
// in them. The header search filters every category here: harnesses keep only
// their matching projects and assets, and a harness with no matches is dropped.
function TreeView(props: InventoryNavProps) {
  const { harnesses, query } = props;
  const ql = query.toLowerCase();
  const matchq = (s: string) => !ql || s.toLowerCase().includes(ql);
  const filtered = ql
    ? harnesses
        .map((h) => ({
          ...h,
          projects: h.projects.filter((p) => matchq(p.name) || matchq(p.repo)),
          categories: h.categories
            .map((c) => ({
              ...c,
              assets: c.assets.filter((it) => matchq(it.name) || matchq(it.sub)),
            }))
            .filter((c) => c.assets.length > 0),
        }))
        .filter(
          (h) =>
            h.projects.length > 0 || h.categories.length > 0 || matchq(h.label) || matchq(h.kind),
        )
    : harnesses;
  return (
    <>
      <SectionLabel iconName="terminal" label="Harnesses" count={filtered.length} />
      <div className="flex flex-col gap-0.5">
        {filtered.length > 0 ? (
          filtered.map((h) => <HarnessTreeRow key={h.id} h={h} {...props} />)
        ) : (
          <EmptyState message={query ? 'No matches' : 'No harnesses detected'} />
        )}
      </div>
    </>
  );
}

function HarnessTreeRow(props: InventoryNavProps & { h: HarnessSummary }) {
  const { h, sel, expanded, onToggleExpand, onSelectHarness, onSelectAsset, query } = props;
  const projects = h.projects;
  const categories = h.categories;
  // Auto-expand while searching so the matches surfaced into this harness are
  // visible without a manual toggle, but let an explicit toggle (true/false in
  // `expanded`) win so the user can still collapse a harness mid-search and have
  // that choice persist once the query is cleared.
  const open = expanded[h.id] ?? (!!query && (projects.length > 0 || categories.length > 0));
  const on = sel?.type === 'harness' && sel.id === h.id;
  const unapproved = (categories.find((c) => c.type === 'mcp')?.assets ?? []).filter(
    (it) => it.trust === 'unapproved',
  ).length;

  return (
    <div>
      {/* Sibling buttons (chevron + row) under a hover wrapper, rather than a
          nested-button. The wrapper carries the hover/selected background so the
          whole row still highlights; each control stays independently focusable. */}
      <div
        className={cn(
          'flex items-center rounded-lg',
          on ? 'bg-primary-tint' : 'hover:bg-surface-2',
        )}
      >
        <button
          type="button"
          aria-label={open ? 'Collapse' : 'Expand'}
          aria-expanded={open}
          onClick={() => {
            onToggleExpand(h.id, !open);
          }}
          className="my-2.5 ml-2.5 grid size-4.5 shrink-0 cursor-pointer place-items-center rounded text-text-3"
        >
          <Ico
            name="chevron-right"
            className={cn('size-3.5 transition-transform', open && 'rotate-90')}
          />
        </button>
        <button
          type="button"
          className="flex min-w-0 flex-1 items-center gap-2.5 p-2.5 text-left cursor-pointer"
          onClick={() => {
            onSelectHarness(h.id);
            if (!open) onToggleExpand(h.id, true);
          }}
        >
          <Provider id={h.id} size={28} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold text-text">{h.label}</div>
            <div className="mt-px text-xs text-text-3">
              {h.kind} · {h.assetCount} assets
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {unapproved > 0 && <span className="size-2 rounded-full bg-sev-critical" />}
            {h.flagCount === 0 ? (
              <Ico name="check-circle" className="size-3.5 text-ok" />
            ) : (
              <span className="rounded-full bg-sev-high px-1.5 py-px text-xs font-bold text-white">
                {h.flagCount}
              </span>
            )}
          </div>
        </button>
      </div>
      {open && (
        <div className="my-0.5 ml-4 border-l border-border pl-2.5">
          {projects.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 px-2 pb-1 pt-2">
                <Ico name={PROJECT_GROUP.icon} className="size-3 text-text-3" />
                <span className="text-label font-bold uppercase tracking-wider text-text-3">
                  {PROJECT_GROUP.label}
                </span>
                <span className="text-label font-semibold text-text-3">{projects.length}</span>
              </div>
              {projects.map((p) => (
                <ProjectNavRow key={p.id} p={p} fromHarness={h.id} {...props} />
              ))}
            </div>
          )}
          {categories.map((c) => {
            const meta = ASSET_META[c.type as Exclude<AssetType, 'project'>];
            return (
              <div key={c.type}>
                <div className="flex items-center gap-1.5 px-2 pb-1 pt-2">
                  <Ico name={meta.icon} className="size-3 text-text-3" />
                  <span className="text-label font-bold uppercase tracking-wider text-text-3">
                    {meta.label}
                  </span>
                  <span className="text-label font-semibold text-text-3">{c.assets.length}</span>
                </div>
                {c.assets.map((it) => (
                  <AssetNavRow
                    key={it.id}
                    it={it}
                    indent
                    fromHarness={h.id}
                    sel={sel}
                    onSelectAsset={onSelectAsset}
                  />
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Type view ───────────────────────────────────────────────────────────────
function TypeView(
  props: InventoryNavProps & { projList: ProjectSummary[]; assetsByType: AssetsByType },
) {
  const { typeFilter, query, projList, assetsByType } = props;
  const ql = query.toLowerCase();
  const matchq = (s: string) => !ql || s.toLowerCase().includes(ql);
  const showType = (t: AssetType) => typeFilter === 'all' || typeFilter === t;

  // In the "All" view, hide empty sections to keep the list tidy — the overall
  // empty state below covers the no-matches case. Under a single-type filter,
  // keep the section visible with its own 'no data' message.
  let rendered = 0;
  const sections = GROUPS.map((g) => {
    if (!showType(g.type)) return null;
    if (g.type === 'project') {
      const count = projList.length;
      if (count === 0 && typeFilter === 'all') return null;
      if (count > 0) rendered++;
      return (
        <div key={g.type}>
          <GroupHeader group={g} items={projFlagItems(projList)} />
          <div className="flex flex-col gap-0.5">
            {count === 0 ? (
              <EmptyState message={`No ${g.label.toLowerCase()}`} />
            ) : (
              projList.map((p) => <ProjectNavRow key={p.id} p={p} {...props} />)
            )}
          </div>
        </div>
      );
    }
    const items = assetsByType[g.type].filter((it) => matchq(it.name) || matchq(it.sub));
    if (items.length === 0 && typeFilter === 'all') return null;
    if (items.length > 0) rendered++;
    return (
      <div key={g.type}>
        <GroupHeader group={g} items={items} mcpItems={g.type === 'mcp' ? items : undefined} />
        <div className="flex flex-col gap-0.5">
          {items.length === 0 ? (
            <EmptyState message={`No ${g.label.toLowerCase()}`} />
          ) : (
            items.map((it) => (
              <AssetNavRow
                key={it.id}
                it={it}
                sel={props.sel}
                onSelectAsset={props.onSelectAsset}
              />
            ))
          )}
        </div>
      </div>
    );
  });

  if (typeFilter === 'all' && rendered === 0) {
    return (
      <EmptyState icon="search" message={query ? `No assets match “${query}”` : 'No assets'} />
    );
  }
  return <>{sections}</>;
}

// ─── Shared rows ─────────────────────────────────────────────────────────────
function ProjectNavRow({
  p,
  fromHarness,
  selFromHarness,
  sel,
  onSelectProject,
}: InventoryNavProps & { p: ProjectSummary; fromHarness?: string | undefined }) {
  const c = p.accessCounts;
  const findings = p.findingsCount;
  // When the same project nests under several harnesses, only highlight the row
  // under the harness it was actually opened from. Two exceptions both highlight
  // unconditionally: by-type rows (`fromHarness == null`, no harness context),
  // and projects opened from the by-type view (`selFromHarness == null`), which
  // light up under every harness that worked in them.
  const on =
    sel?.type === 'project' &&
    sel.id === p.id &&
    (fromHarness == null || selFromHarness == null || fromHarness === selFromHarness);
  return (
    <button
      type="button"
      onClick={() => {
        onSelectProject(p.id, fromHarness);
      }}
      className={cn(
        'flex w-full flex-col rounded-lg p-2.5 text-left cursor-pointer',
        on ? 'bg-primary-tint' : 'hover:bg-surface-2',
      )}
    >
      <div className="mb-1.5 flex items-center gap-2.5">
        <span
          className="size-2 shrink-0 rounded-full"
          style={{ background: langColor(p.language) }}
        />
        <span className="truncate text-sm font-semibold text-text">{p.name}</span>
        <span className="ml-auto shrink-0">
          <VisBadge v={p.visibility} />
        </span>
      </div>
      <div className="mb-2 flex items-center gap-1.5 font-mono text-xs text-text-3">
        <Ico name="repo" className="size-3" />
        {p.repo}
      </div>
      <div className="flex items-center gap-2.5">
        <AccessBar counts={c} />
        {c.blocked > 0 ? (
          <span className="text-xs font-semibold text-sev-critical">{c.blocked} blocked</span>
        ) : (
          <span className="text-xs text-text-3">{c.total} files</span>
        )}
        {findings > 0 && (
          <span className="ml-auto shrink-0">
            <FlagChips flags={['findings']} mini />
          </span>
        )}
      </div>
    </button>
  );
}

function AssetNavRow({
  it,
  indent,
  fromHarness,
  sel,
  onSelectAsset,
}: {
  it: AssetSummary;
  indent?: boolean;
  fromHarness?: string | undefined;
  sel: Selection | null;
  onSelectAsset: (it: AssetSummary, fromHarness?: string) => void;
}) {
  const on = sel?.type === it.type && sel.id === it.id;
  const tile = assetTile(it.type);
  const trust = it.type === 'mcp' ? it.trust : undefined;
  return (
    <button
      type="button"
      onClick={() => {
        onSelectAsset(it, fromHarness);
      }}
      className={cn(
        'flex w-full items-center gap-2.5 rounded-lg py-3 text-left cursor-pointer',
        indent ? 'px-3' : 'px-2.5',
        on ? 'bg-primary-tint' : 'hover:bg-surface-2',
      )}
    >
      <span
        className={cn('grid size-7.5 shrink-0 place-items-center rounded-md', tile.bg, tile.fg)}
      >
        <Ico name={tile.icon} className="size-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-xs font-semibold text-text">{it.name}</div>
        <div className="mt-0.5 truncate font-mono text-label text-text-3">{it.sub}</div>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        {trust && <TrustPill value={trust} />}
        {it.flags.length > 0 && <FlagChips flags={it.flags} mini />}
      </div>
    </button>
  );
}

function GroupHeader({
  group,
  items,
  mcpItems,
}: {
  group: TypeMeta;
  items: { flags: Flag[] }[];
  mcpItems?: AssetSummary[] | undefined;
}) {
  const parts = rollup(items);
  const trustRoll = mcpItems
    ? (['unapproved', 'risky'] as const)
        .map((k) => ({ k, n: mcpItems.filter((it) => it.trust === k).length }))
        .filter((x) => x.n)
    : [];
  return (
    <div className="flex items-center gap-2 px-2.5 pb-1.5 pt-3">
      <span className={cn('grid size-5 shrink-0 place-items-center rounded', group.bg, group.fg)}>
        <Ico name={group.icon} className="size-3" />
      </span>
      <span className="text-xs font-bold uppercase tracking-wider text-text-2">{group.label}</span>
      <span className="text-xs font-semibold text-text-3">{items.length}</span>
      <span className="ml-auto inline-flex flex-wrap items-center justify-end gap-1.5">
        {trustRoll.map((x) => (
          <Badge key={x.k} variant={TRUST[x.k].tone}>
            {x.n} {TRUST[x.k].label.toLowerCase()}
          </Badge>
        ))}
        {parts.map((x) => (
          <Badge key={x.key} variant={FLAG[x.key].tone}>
            {x.count} {FLAG[x.key].short.toLowerCase()}
          </Badge>
        ))}
      </span>
    </div>
  );
}

function SectionLabel({
  iconName,
  label,
  count,
}: {
  iconName: IconName;
  label: string;
  count: number;
}) {
  return (
    <div className="flex items-center gap-2 px-2.5 pb-1.5 pt-3">
      <span className="grid size-5 shrink-0 place-items-center rounded bg-surface-2 text-text-2">
        <Ico name={iconName} className="size-3" />
      </span>
      <span className="text-xs font-bold uppercase tracking-wider text-text-2">{label}</span>
      <span className="text-xs font-semibold text-text-3">{count}</span>
    </div>
  );
}
