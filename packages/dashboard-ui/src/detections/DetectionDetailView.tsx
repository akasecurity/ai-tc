'use client';
// The right-hand detail pane: a detection's header (with an optional enable/disable
// toggle), provenance/library lineage, the enforcement-policy picker, and its rules.
//
// Action callbacks are all optional so one body serves both dashboards (mirrors
// FindingDetailView's optional footer):
//   - onToggleEnabled : present ⇒ live Switch; absent ⇒ static Enabled/Disabled badge
//   - onChangePolicy  : present ⇒ interactive PolicyPicker (OSS); absent ⇒ read-only
//   - unavailablePolicies : ids this host can render but not assign, each with a
//     reason. Interactive AND restricted is a real combination — a control plane
//     that writes policy but cannot deliver a reversible archetype to a device.
//   - policyFloor     : what an attached machine's organization requires for THIS
//     detection. Folded into the same restricted set, so the options offered are
//     the options the store will accept.
//   - policyError     : a write the store refused, in the user's words. Rendered
//     at the control that produced it, because a refusal reported nowhere is
//     indistinguishable from a picker that quietly ignores you.
//   - onOpenUpdate    : present + update available ⇒ Update button in the provenance
import type { DetectionDetail, DetectionRule } from '@akasecurity/schema';
import { Button, SeverityBadge, Switch, toneColors } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { SectionLabel } from '../shared/DetailFields.tsx';
import { ChevronRightIcon, MoreVertIcon, PlusIcon } from '../shared/icons.tsx';
import { CATEGORY_LABEL, MATCHER_META, matcherSummary, policyMeta } from './meta.ts';
import {
  type DetectionPolicyFloor,
  effectivePolicyId,
  unavailableUnderFloor,
} from './policy-floor.ts';
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
            <span className="truncate text-sm font-semibold text-text" title={rule.name}>
              {rule.name}
            </span>
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
  unavailablePolicies,
  policyFloor,
  policyError,
  onOpenUpdate,
  onRecheck,
  unknownHint,
}: {
  d: DetectionDetail;
  onOpenRule: (id: string) => void;
  onToggleEnabled?: (() => void) | undefined;
  onChangePolicy?: ((policyId: string) => void) | undefined;
  /**
   * Policy ids this host cannot assign, mapped to why — passed straight to
   * PolicyPicker. A host that knows of no restriction omits it.
   */
  unavailablePolicies?: Readonly<Record<string, string>> | undefined;
  /**
   * The control-plane constraint on this detection, or null/absent when the
   * machine is its own authority. Restricts the picker to the archetypes the
   * local store will actually accept — a machine may raise its organization's
   * requirement, never lower it, and a detection the organization has written a
   * policy for is not re-assignable here at all.
   */
  policyFloor?: DetectionPolicyFloor | null | undefined;
  /** A refused or failed policy write, already worded for the reader. */
  policyError?: string | null | undefined;
  onOpenUpdate?: (() => void) | undefined;
  // Re-read the update state in place (the OSS web-ui's "Check again" for the
  // unknown provenance state); omitted by apps with their own refresh flow.
  onRecheck?: (() => void) | undefined;
  // App-supplied copy for the unknown provenance state (see ProvenanceBlock) —
  // the "how an inventory gets recorded" hint differs per app.
  unknownHint?: ReactNode;
}) {
  // What is ENFORCED, not merely what is stored: a store written before this
  // machine was attached can hold an assignment weaker than the organization
  // requires, and enforcement raises it. The description card below explains the
  // archetype the picker shows as selected, so the two must be the same one.
  const policyId = effectivePolicyId(d.policyId, policyFloor);
  const policy = policyMeta(policyId);
  const PolicyMetaIcon = policy.icon;
  // Two sources of restriction, merged rather than chosen between: a host can
  // both be unable to deliver an archetype AND be under an organization's floor.
  // Undefined when neither restricts anything, so an unconstrained detection
  // renders the control it rendered before either prop existed.
  const floorRestrictions = unavailableUnderFloor(policyFloor);
  const restricted =
    unavailablePolicies === undefined && floorRestrictions === undefined
      ? undefined
      : { ...unavailablePolicies, ...floorRestrictions };

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
              <span
                className={'text-ui font-semibold ' + (d.enabled ? 'text-ok-ink' : 'text-text-3')}
              >
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
          <PolicyPicker value={policyId} onChange={onChangePolicy} unavailable={restricted} />
          {policyError && (
            // At the control, not in a page-level banner: the user's next move is
            // to pick something else, and a message they have to go and find
            // reads as the page failing rather than as this choice being refused.
            <p className="mt-2 text-xs text-sev-critical-ink" data-slot="policy-write-error">
              {policyError}
            </p>
          )}
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
