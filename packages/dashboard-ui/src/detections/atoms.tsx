// Small shared presentational atoms for the Detections views: tone-colored pills,
// provenance badges, and metadata bits. Data-driven colors are applied as inline
// styles sourced from theme-token CSS vars via toneColors. Pure (no state/events)
// so they render in any host app.
import type { OriginEnum, PublisherKind } from '@akasecurity/schema';
import { type ReactNode } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { ArrowUpIcon, BranchIcon } from '../shared/icons.tsx';
import { ORIGIN_META, policyMeta, PUBLISHER_META, type Tone, toneColors } from './meta.ts';

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

/** A tone-colored pill for a detection's assigned enforcement policy. */
export function PolicyTag({ policy }: { policy: string }) {
  const m = policyMeta(policy);
  const [fg, bg] = toneColors(m.tone);
  const Icon = m.icon;
  return (
    <span
      className="inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded-full px-2 text-xs font-semibold"
      style={{ color: fg, background: bg }}
    >
      <Icon aria-hidden focusable={false} className="size-3" />
      {m.label}
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
    <TonePill tone="blue" icon={BranchIcon}>
      Customized
    </TonePill>
  );
}

export function UpdateBadge({ version }: { version?: string | undefined }) {
  return (
    <span className="inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full bg-sev-high-fill px-2 text-xs font-semibold text-sev-high">
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
      <span className="truncate">{publisher}</span>
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
