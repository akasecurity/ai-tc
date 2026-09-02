// Small shared presentational atoms for the Detections views: tone-colored pills,
// provenance badges, and metadata bits. Data-driven colors are applied as inline
// styles sourced from theme-token CSS vars via toneColors. Pure (no state/events)
// so they render in any host app.
import type { OriginEnum, PublisherKind } from '@akasecurity/schema';
import { type Tone, toneColors } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { ArrowUpIcon, BranchIcon, BuildingIcon } from '../shared/icons.tsx';
import { ORIGIN_META, policyMeta, PUBLISHER_META } from './meta.ts';
import {
  type DetectionPolicyFloor,
  effectivePolicyId,
  isPolicyGoverned,
  policyFloorReason,
} from './policy-floor.ts';

/** A small tone-colored pill (the design's `badge`). */
export function TonePill({
  tone,
  icon: Icon,
  children,
  className,
}: {
  tone: Tone;
  icon?: IconComponent;
  children: ReactNode;
  className?: string;
}) {
  const [fg, bg] = toneColors(tone);
  return (
    <span
      className={
        'inline-flex h-[22px] items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-xs font-semibold ' +
        (className ?? '')
      }
      style={{ color: fg, background: bg }}
    >
      {Icon && <Icon aria-hidden focusable={false} className="size-3" />}
      {children}
    </span>
  );
}

/**
 * A tone-colored pill for a detection's enforcement policy.
 *
 * With a `floor`, it names what is ENFORCED rather than what is stored: an
 * attached machine's organization can require more than the local assignment
 * asks for, and a store written before that constraint existed can still hold
 * the weaker value. A pill reading Monitor beside a detection whose matches are
 * being warned about is the same untruth the picker used to tell.
 *
 * Optional, and inert when omitted — a standalone machine is its own authority,
 * and its rows render exactly as they did before.
 */
export function PolicyTag({
  policy,
  floor,
}: {
  policy: string;
  floor?: DetectionPolicyFloor | null | undefined;
}) {
  const shown = effectivePolicyId(policy, floor);
  const governed = isPolicyGoverned(policy, floor);
  const m = policyMeta(shown);
  const [fg, bg] = toneColors(m.tone);
  const Icon = m.icon;
  // Non-null whenever `governed` is: both require a floor. Read through a
  // conditional anyway so the reason and the marker cannot come apart.
  const reason = governed && floor ? policyFloorReason(floor) : undefined;
  return (
    <span
      className="inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-xs font-semibold"
      style={{ color: fg, background: bg }}
      title={reason}
    >
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
      {reason !== undefined && (
        <>
          {/* The glyph says "not this machine's decision"; `title` is invisible
              on touch and unreliable for assistive tech, so the sentence itself
              is carried in text only a screen reader reads. The pill sits inside
              a row button where visible prose has nowhere to go — the detail
              pane is where the same sentence is shown to everyone. */}
          <BuildingIcon aria-hidden focusable={false} className="size-3" />
          <span className="sr-only">{reason}</span>
        </>
      )}
    </span>
  );
}

export function OriginBadge({ origin }: { origin: OriginEnum }) {
  const m = ORIGIN_META[origin];
  return (
    <TonePill tone={m.tone} icon={m.icon}>
      {m.label}
    </TonePill>
  );
}

export function BranchBadge() {
  return (
    <TonePill tone="low" icon={BranchIcon}>
      Customized
    </TonePill>
  );
}

export function UpdateBadge({ version }: { version?: string | undefined }) {
  return (
    <span className="inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full bg-sev-high-fill px-2 text-xs font-semibold text-sev-high-ink">
      <ArrowUpIcon aria-hidden focusable={false} className="size-3" />
      {version ? 'Update · v' + version : 'Update'}
    </span>
  );
}

export function PublisherTag({ publisher, kind }: { publisher: string; kind: PublisherKind }) {
  const m = PUBLISHER_META[kind];
  const [fg] = toneColors(m.tone);
  const Icon = m.icon;
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5 text-xs font-semibold text-text-2">
      <Icon aria-hidden focusable={false} className="size-3.5 shrink-0" style={{ color: fg }} />
      <span className="truncate" title={publisher}>
        {publisher}
      </span>
      {m.verified && (
        <span title={m.label} className="text-[10px] font-bold" style={{ color: fg }}>
          ✓
        </span>
      )}
    </span>
  );
}

export function MetaStat({ icon: Icon, children }: { icon: IconComponent; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 text-xs font-medium text-text-3">
      <Icon aria-hidden focusable={false} className="size-3.5 text-text-3" />
      {children}
    </span>
  );
}
