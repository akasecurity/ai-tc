'use client';

// Right pane shown when a harness (Claude Code / Cursor / Codex) is selected:
// recent block/redact/warn events (GET /v1/inventory/harnesses/:id/events), an
// attention banner, the harness's projects, and per-category asset mini-lists.
import type {
  AssetSummary,
  AssetType,
  HarnessEventKind,
  HarnessEventsResponse,
  HarnessSummary,
  ProjectSummary,
} from '@akasecurity/schema';
import { Badge, cn } from '@akasecurity/ui-kit';

import { Provider } from '../shared/Provider.tsx';
import { AccessBar, EmptyState, FlagChips, TrustPill, VisBadge } from './chips.tsx';
import { ASSET_META, assetTile, EVENT_KIND, langColor } from './data.ts';
import { Ico } from './Ico.tsx';

const EVENT_KINDS: HarnessEventKind[] = ['block', 'redact', 'warn'];

/** Format an ISO timestamp into the "Today · 09:19" day/time the row shows. */
function formatEvent(iso: string): { day: string; time: string } {
  const d = new Date(iso);
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const today = new Date();
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const dayDiff = Math.round((startOf(today) - startOf(d)) / 86_400_000);
  const day =
    dayDiff === 0
      ? 'Today'
      : dayDiff === 1
        ? 'Yesterday'
        : d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  return { day, time };
}

export function HarnessOverview({
  harness,
  events,
  onSelect,
  onSelectProject,
}: {
  harness: HarnessSummary;
  events: HarnessEventsResponse | null;
  onSelect: (it: AssetSummary) => void;
  onSelectProject: (id: string) => void;
}) {
  const mcpItems = harness.categories.find((c) => c.type === 'mcp')?.assets ?? [];
  const unapproved = mcpItems.filter((it) => it.trust === 'unapproved').length;
  const items = events?.items ?? [];
  const counts = events?.counts;
  // counts is computed server-side over ALL events; items is capped (limit=7),
  // so surface the truncation instead of showing badges that outnumber the rows.
  const totalEvents = counts ? counts.block + counts.redact + counts.warn : 0;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* header */}
      <div className="flex items-center gap-3 border-b border-border px-5 py-4">
        <Provider id={harness.id} size={38} />
        <div className="min-w-0 flex-1">
          <div className="font-display text-base font-semibold">{harness.label}</div>
          <div className="mt-px text-xs text-text-3">
            {harness.kind} · {harness.version}
          </div>
        </div>
      </div>

      {/* body */}
      <div className="flex min-h-0 flex-1 flex-col gap-4.5 overflow-y-auto p-5">
        {/* recent detection outcomes */}
        <div>
          <div className="mb-2.5 flex items-center gap-2">
            <span className="text-label font-semibold uppercase tracking-wider text-text-3">
              Recent blocks, redactions &amp; warnings
            </span>
            {counts && (
              <span className="ml-auto inline-flex items-center gap-1.5">
                {EVENT_KINDS.map((k) => {
                  const n = counts[k];
                  return n > 0 ? (
                    <Badge key={k} variant={EVENT_KIND[k].tone}>
                      {n} {EVENT_KIND[k].label.toLowerCase()}
                    </Badge>
                  ) : null;
                })}
              </span>
            )}
          </div>
          {items.length === 0 ? (
            <div className="flex items-center gap-2.5 rounded-lg border border-dashed border-border-strong px-3 py-3.5 text-text-3">
              <Ico name="check-circle" className="size-4 text-ok" />
              <span className="text-xs">No blocks, redactions or warnings from this harness</span>
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {items.map((x) => {
                const m = EVENT_KIND[x.kind];
                const { day, time } = formatEvent(x.occurredAt);
                return (
                  <div
                    key={`${x.occurredAt}·${x.title}`}
                    className="flex items-start gap-2.5 rounded-lg border border-border bg-surface px-3 py-2.5"
                  >
                    <span
                      className={cn(
                        'grid size-7 shrink-0 place-items-center rounded-md',
                        m.bg,
                        m.fg,
                      )}
                    >
                      <Ico name={m.icon} className="size-3.5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-semibold text-text">{x.title}</div>
                      <div className="mt-0.5 truncate font-mono text-xs text-text-3">
                        {x.detail}
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <Badge variant={m.tone}>{m.label}</Badge>
                      <span className="font-mono text-xs text-text-3">
                        {day} · {time}
                      </span>
                    </div>
                  </div>
                );
              })}
              {totalEvents > items.length && (
                <div className="pt-0.5 text-center text-xs text-text-3">
                  Showing {items.length} of {totalEvents} events
                </div>
              )}
            </div>
          )}
        </div>

        {/* attention / trust banner */}
        {(harness.flagCount > 0 || unapproved > 0) && (
          <div className="flex items-center gap-2.5 rounded-lg border border-border bg-sev-high-fill px-3 py-2.5">
            <Ico name="flag" className="size-4 shrink-0 text-sev-high" />
            <div className="text-xs font-medium text-text">
              {harness.flagCount > 0 &&
                `${String(harness.flagCount)} item${harness.flagCount === 1 ? '' : 's'} need review`}
              {harness.flagCount > 0 && unapproved > 0 && ' · '}
              {unapproved > 0 &&
                `${String(unapproved)} unapproved MCP${unapproved === 1 ? '' : 's'}`}
            </div>
          </div>
        )}

        {/* projects this harness has worked in */}
        {harness.projects.length > 0 && (
          <div>
            <div className="mb-2 flex items-center gap-1.5">
              <span className="text-label font-semibold uppercase tracking-wider text-text-3">
                Projects
              </span>
              <span className="text-xs font-semibold text-text-3">{harness.projects.length}</span>
            </div>
            <div className="flex flex-col gap-1.5">
              {harness.projects.map((p) => (
                <ProjectMini key={p.id} p={p} onSelect={onSelectProject} />
              ))}
            </div>
          </div>
        )}

        {/* per-category lists */}
        {harness.categories.length === 0 && harness.projects.length === 0 && (
          <EmptyState message="No projects, skills, MCP servers, hooks or configuration for this harness" />
        )}
        {harness.categories.map((c) => {
          const meta = ASSET_META[c.type as Exclude<AssetType, 'project'>];
          return (
            <div key={c.type}>
              <div className="mb-2 flex items-center gap-1.5">
                <span className="text-label font-semibold uppercase tracking-wider text-text-3">
                  {meta.label}
                </span>
                <span className="text-xs font-semibold text-text-3">{c.assets.length}</span>
              </div>
              <div className="flex flex-col gap-1.5">
                {c.assets.map((it) => (
                  <AssetMini key={it.id} it={it} onSelect={onSelect} />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ProjectMini({ p, onSelect }: { p: ProjectSummary; onSelect: (id: string) => void }) {
  const counts = p.accessCounts;
  return (
    <button
      type="button"
      onClick={() => {
        onSelect(p.id);
      }}
      className="flex w-full items-center gap-2.5 rounded-lg border border-border bg-surface px-2.5 py-2 text-left cursor-pointer hover:bg-surface-2"
    >
      <span
        className="size-2.5 shrink-0 rounded-full"
        style={{ background: langColor(p.language) }}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-xs font-semibold text-text">{p.name}</span>
          <VisBadge v={p.visibility} />
        </div>
        <div className="mt-0.5 flex items-center gap-1.5 truncate font-mono text-xs text-text-3">
          <Ico name="repo" className="size-3 shrink-0" />
          {p.repo}
        </div>
      </div>
      <AccessBar counts={counts} />
      {counts.blocked > 0 && (
        <span className="text-xs font-semibold text-sev-critical">{counts.blocked} blocked</span>
      )}
      {p.findingsCount > 0 && <FlagChips flags={['findings']} mini />}
      <Ico name="chevron-right" className="size-4 shrink-0 text-text-3" />
    </button>
  );
}

function AssetMini({ it, onSelect }: { it: AssetSummary; onSelect: (it: AssetSummary) => void }) {
  const tile = assetTile(it.type);
  const trust = it.type === 'mcp' ? it.trust : undefined;
  return (
    <button
      type="button"
      onClick={() => {
        onSelect(it);
      }}
      className="flex w-full items-center gap-2.5 rounded-lg border border-border bg-surface px-2.5 py-2 text-left cursor-pointer hover:bg-surface-2"
    >
      <span
        className={cn('grid size-6.5 shrink-0 place-items-center rounded-md', tile.bg, tile.fg)}
      >
        <Ico name={tile.icon} className="size-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-xs font-semibold text-text">{it.name}</div>
        <div className="truncate font-mono text-xs text-text-3 mt-0.5">{it.sub}</div>
      </div>
      {trust && <TrustPill value={trust} />}
      {it.flags.length > 0 && <FlagChips flags={it.flags} mini />}
      <Ico name="chevron-right" className="size-4 shrink-0 text-text-3" />
    </button>
  );
}
