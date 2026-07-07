'use client';

// Presentational Policies views — the built-in enforcement-policy catalog with a
// master/detail layout. Props-driven and data-fetching-free (a host feeds the
// same components via client hooks or @akasecurity/persistence Server
// Components). Icon + tone come
// from the shared policyMeta / toneColors (the same source the detections
// PolicyPicker uses), so the swatch never drifts from the picker.
import type { PolicyDetail, PolicyListItem, PolicyStatsResponse } from '@akasecurity/schema';
import { Card, cn, Tag } from '@akasecurity/ui-kit';

import { policyMeta, toneColors } from '../detections/meta.ts';
import { ListIcon, LockIcon, PolicyIcon, ShieldCheckIcon, TerminalIcon } from '../shared/icons.tsx';
import { StatTile } from '../shared/StatTile.tsx';

/** Stat value once settled: the number, or an em dash when still unknown. */
function statValue(n: number | undefined): string {
  return n === undefined ? '—' : String(n);
}

/** The four-tile stat strip above the Policies master/detail. */
export function PolicyStatsView({
  stats,
  loading = false,
}: {
  stats: PolicyStatsResponse | null | undefined;
  loading?: boolean;
}) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatTile
        icon={PolicyIcon}
        iconBg="var(--color-primary-tint)"
        iconColor="var(--color-primary)"
        label="Policies"
        value={statValue(stats?.policies)}
        loading={loading}
      />
      <StatTile
        icon={ShieldCheckIcon}
        iconBg="var(--color-surface-2)"
        iconColor="var(--color-text-2)"
        label="Built-in"
        value={statValue(stats?.builtin)}
        loading={loading}
      />
      <StatTile
        icon={TerminalIcon}
        iconBg="var(--color-violet-fill)"
        iconColor="var(--color-violet)"
        label="Custom scripts"
        value={statValue(stats?.custom)}
        loading={loading}
      />
      <StatTile
        icon={ListIcon}
        iconBg="var(--color-ok-fill)"
        iconColor="var(--color-ok)"
        label="Detections governed"
        value={statValue(stats?.detectionsGoverned)}
        loading={loading}
      />
    </div>
  );
}

function PolicyRow({
  policy,
  selected,
  onSelect,
}: {
  policy: PolicyListItem;
  selected: boolean;
  onSelect: () => void;
}) {
  const { icon: Icon, tone } = policyMeta(policy.id);
  const [fg, bg] = toneColors(tone);
  const count = policy.usedByCount;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        'flex w-full cursor-pointer items-center gap-3 rounded-lg p-3 text-left transition-colors',
        selected ? 'bg-primary-tint' : 'hover:bg-surface-2',
      )}
    >
      <span
        className="flex size-7.5 shrink-0 items-center justify-center rounded-lg [&_svg]:size-4"
        style={{ background: bg, color: fg }}
      >
        <Icon aria-hidden focusable={false} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold text-text">{policy.name}</span>
        <span className="mt-px block text-xs text-text-3">
          {count} detection{count === 1 ? '' : 's'}
        </span>
      </span>
      {policy.kind === 'builtin' && (
        <LockIcon aria-hidden focusable={false} className="size-3.5 shrink-0 text-text-3" />
      )}
    </button>
  );
}

/** The left master list Card — the built-in policy catalog. */
export function PolicyListView({
  items,
  activeId,
  onSelect,
  loading = false,
  error = null,
}: {
  items: PolicyListItem[];
  activeId?: string | undefined;
  onSelect: (id: string) => void;
  loading?: boolean;
  error?: string | null;
}) {
  return (
    <Card className="flex flex-col overflow-hidden p-2 shadow-sm">
      <div className="mb-1 px-2.5 pb-1 pt-2 text-label font-semibold uppercase tracking-wider text-text-3">
        Policies
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto">
        {error ? (
          <p className="px-2.5 py-2 text-sm text-sev-critical">Error loading policies: {error}</p>
        ) : loading ? (
          <p className="px-2.5 py-2 text-sm text-text-3">Loading policies…</p>
        ) : items.length === 0 ? (
          <p className="px-2.5 py-2 text-sm text-text-3">No policies yet.</p>
        ) : (
          items.map((policy) => (
            <PolicyRow
              key={policy.id}
              policy={policy}
              selected={policy.id === activeId}
              onSelect={() => {
                onSelect(policy.id);
              }}
            />
          ))
        )}
      </div>
    </Card>
  );
}

/** The right detail pane body (the app wraps this in a scrolling Card). */
export function PolicyDetailView({ policy }: { policy: PolicyDetail }) {
  const { icon: Icon, tone } = policyMeta(policy.id);
  const [fg, bg] = toneColors(tone);
  const isBuiltin = policy.kind === 'builtin';
  const detections = policy.usedBy;
  return (
    <div className="flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-5 py-4">
        <span
          className="flex size-11 shrink-0 items-center justify-center rounded-xl [&_svg]:size-5.5"
          style={{ background: bg, color: fg }}
        >
          <Icon aria-hidden focusable={false} />
        </span>
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <h2 className="font-display text-xl font-semibold text-text">{policy.name}</h2>
            {isBuiltin && (
              <Tag icon={<LockIcon aria-hidden focusable={false} className="size-3" />}>
                Built-in
              </Tag>
            )}
            <span className="rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs font-semibold text-text-2">
              {policy.id}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-text-3">
            {isBuiltin ? 'AKA · built-in · no configuration' : 'Custom policy'}
          </p>
        </div>
      </div>
      <div className="flex flex-col gap-6 p-5">
        {/* Description + fixed note */}
        <div className="rounded-xl border border-border bg-surface-2 px-4 py-3">
          <p className="text-sm leading-relaxed text-text">{policy.description}</p>
          {isBuiltin && (
            <p className="mt-2 inline-flex items-center gap-1.5 text-xs text-text-3">
              <LockIcon aria-hidden focusable={false} className="size-3.5" />
              Built-in policy — behavior is fixed and can&apos;t be edited.
            </p>
          )}
        </div>

        {/* Applied by */}
        <div>
          <div className="mb-2.5 flex items-center gap-2">
            <span className="text-label font-semibold uppercase tracking-wider text-text-3">
              Applied by
            </span>
            <span className="rounded-full bg-surface-3 px-2 py-0.5 text-xs font-semibold text-text-2">
              {detections.length}
            </span>
          </div>
          {detections.length === 0 ? (
            <p className="py-2 text-sm text-text-3">No detections use this policy yet.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {detections.map((d) => (
                <Tag
                  key={d.id}
                  className="h-7"
                  dot={d.enabled ? 'var(--color-ok)' : 'var(--color-border-strong)'}
                >
                  {d.name}
                  <span className="font-mono text-text-3">{d.ruleCount} rules</span>
                </Tag>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
