'use client';
// The right-hand detail pane: a detection's header (with an optional enable/disable
// toggle), provenance/library lineage, the enforcement-policy picker, and its rules.
//
// Action callbacks are all optional so one body serves both dashboards (mirrors
// FindingDetailView's optional footer):
//   - onToggleEnabled : present ⇒ live Switch; absent ⇒ static Enabled/Disabled badge
//   - onChangePolicy  : present ⇒ interactive PolicyPicker (OSS); absent ⇒ read-only
//   - onOpenUpdate    : present + update available ⇒ Update button in the provenance
import type { DetectionDetail, DetectionRule } from '@akasecurity/schema';
import { Button, SeverityBadge, Switch } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { SectionLabel } from '../shared/DetailFields.tsx';
import { ChevronRightIcon, MoreVertIcon, PlusIcon } from '../shared/icons.tsx';
import {
  CATEGORY_LABEL,
  MATCHER_META,
  matcherSummary,
  PLACEHOLDER_POLICY,
  policyMeta,
  toneColors,
} from './meta.ts';
import { PolicyPicker } from './PolicyPicker.tsx';
import { ProvenanceBlock } from './ProvenanceBlock.tsx';

function RuleCard({ rule, onOpen }: { rule: DetectionRule; onOpen: () => void }) {
  const mm = MATCHER_META[rule.matcher.type];
  const Icon: IconComponent = mm.icon;
  return (
    <div className="rounded-xl border border-border bg-surface p-3.5">
      <div className="mb-2.5 flex items-center gap-2.5">
        <span
          className="grid size-7.5 shrink-0 place-items-center rounded-lg"
          style={{ background: mm.fill, color: mm.color }}
        >
          <Icon aria-hidden focusable={false} className="size-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-semibold text-text">{rule.name}</span>
            <span className="text-xs text-text-3">
              {CATEGORY_LABEL[rule.category] || rule.category}
            </span>
          </div>
          <div className="mt-px font-mono text-label text-text-3">{rule.id}</div>
        </div>
        <SeverityBadge severity={rule.severity} />
        <span
          className="shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold"
          style={{ background: mm.fill, color: mm.color }}
        >
          {mm.label}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-text-2">
          {matcherSummary(rule.matcher)}
        </code>
        <Button variant="ghost" tone="primary" size="sm" onClick={onOpen} className="shrink-0">
          View
          <ChevronRightIcon aria-hidden focusable={false} className="size-3.5" />
        </Button>
      </div>
    </div>
  );
}

export function DetectionDetailView({
  d,
  onOpenRule,
  onToggleEnabled,
  onChangePolicy,
  onOpenUpdate,
  onRecheck,
  unknownHint,
}: {
  d: DetectionDetail;
  onOpenRule: (id: string) => void;
  onToggleEnabled?: (() => void) | undefined;
  onChangePolicy?: ((policyId: string) => void) | undefined;
  onOpenUpdate?: (() => void) | undefined;
  // Re-read the update state in place (the OSS web-ui's "Check again" for the
  // unknown provenance state); omitted by apps with their own refresh flow.
  onRecheck?: (() => void) | undefined;
  // App-supplied copy for the unknown provenance state (see ProvenanceBlock) —
  // the "how an inventory gets recorded" hint differs per app.
  unknownHint?: ReactNode;
}) {
  const policyId = d.policyId ?? PLACEHOLDER_POLICY;
  const policy = policyMeta(policyId);
  const PolicyMetaIcon = policy.icon;

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* header */}
      <div className="border-b border-border px-5 pb-4 pt-5">
        <div className="flex items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="font-display text-xl font-semibold text-text">{d.name}</h2>
              <span className="rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-xs font-semibold text-text-2">
                v{d.version}
              </span>
            </div>
            {d.description && (
              <div className="mt-1.5 text-ui leading-snug text-text-2">{d.description}</div>
            )}
            <div className="mt-2 font-mono text-xs text-text-3">{d.id}</div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <div className="flex items-center gap-2">
              <span className={'text-ui font-semibold ' + (d.enabled ? 'text-ok' : 'text-text-3')}>
                {d.enabled ? 'Enabled' : 'Disabled'}
              </span>
              {onToggleEnabled && (
                <Switch
                  checked={d.enabled}
                  onCheckedChange={onToggleEnabled}
                  aria-label={d.enabled ? 'Disable detection' : 'Enable detection'}
                />
              )}
            </div>
            <Button
              variant="ghost"
              tone="neutral"
              size="icon"
              aria-label="More"
              className="size-8.5 text-text-3"
            >
              <MoreVertIcon aria-hidden focusable={false} />
            </Button>
          </div>
        </div>
      </div>

      {/* scroll body */}
      <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-5">
        <ProvenanceBlock
          d={d}
          onOpenUpdate={onOpenUpdate}
          onRecheck={onRecheck}
          unknownHint={unknownHint}
        />

        {/* policy block */}
        <div>
          <div className="mb-2.5 flex items-baseline gap-2">
            <SectionLabel>Enforcement policy</SectionLabel>
            <span className="text-xs text-text-3">applied to every matching request</span>
          </div>
          <PolicyPicker value={policyId} onChange={onChangePolicy} />
          <div className="mt-3 flex items-start gap-2.5 rounded-lg border border-border bg-surface-2 px-3 py-2.5">
            <PolicyMetaIcon
              aria-hidden
              focusable={false}
              className="mt-px size-4 shrink-0"
              style={{ color: toneColors(policy.tone)[0] }}
            />
            <div className="text-xs leading-snug text-text-2">{policy.desc}</div>
          </div>
        </div>

        {/* rules */}
        <div>
          <div className="mb-3 flex items-center gap-2.5">
            <SectionLabel>Rules</SectionLabel>
            <span className="rounded-full bg-surface-3 px-2 py-px text-xs font-semibold text-text-2">
              {d.rules.length}
            </span>
            <span className="flex-1" />
            {/* Rule authoring is not available — the button stays disabled. */}
            <Button
              variant="outline"
              tone="neutral"
              size="sm"
              disabled
              title="Rule authoring coming soon"
            >
              <PlusIcon aria-hidden focusable={false} />
              Add rule
            </Button>
          </div>
          <div className="flex flex-col gap-2.5">
            {d.rules.map((r) => (
              <RuleCard
                key={r.id}
                rule={r}
                onOpen={() => {
                  onOpenRule(r.id);
                }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
