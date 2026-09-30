'use client';

// Small shared presentational pieces for the Inventory page: icon helper,
// colored icon toggles (LLM access · MCP trust), labels, bars and status chips.
import type {
  AccessCounts,
  AccessLevel,
  Flag,
  Origin,
  TrustLevel,
  Visibility,
} from '@akasecurity/schema';
import { Badge, cn, SegmentedControl, SegmentedControlItem } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import { RefusalReason, refusedControlProps } from '../shared/Refusal.tsx';
import { ACCESS, ACCESS_ORDER, FLAG, originMeta, TRUST } from './data.ts';
import { Ico } from './Ico.tsx';
import { type IconName } from './icons.ts';

interface ToggleMeta {
  label: string;
  icon: IconName;
  fg: string;
  bg: string;
}
/**
 * Generic colored single-select icon toggle (used for access & trust), built on
 * ui-kit's SegmentedControl (Radix ToggleGroup) for roving-focus keyboard nav.
 * The selected tone is data-driven, so we neutralize the primitive's default
 * `data-[state=on]` surface styling and apply each option's own fg/bg instead.
 */
function IconToggle<T extends string>({
  order,
  meta,
  value,
  onChange,
}: {
  order: T[];
  meta: Record<T, ToggleMeta>;
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    // wrapper stops a toggle click from also selecting the surrounding row
    <span
      className="inline-flex"
      onClick={(e) => {
        e.stopPropagation();
      }}
    >
      <SegmentedControl
        value={value}
        onValueChange={(v) => {
          if (v) onChange(v as T);
        }}
      >
        {order.map((k) => {
          const m = meta[k];
          const on = k === value;
          return (
            <SegmentedControlItem
              key={k}
              value={k}
              title={m.label}
              className={cn(
                'size-7 flex-none gap-0 px-0 py-0',
                'data-[state=on]:bg-transparent data-[state=on]:text-current data-[state=on]:shadow-none',
                on ? cn(m.fg, m.bg) : 'text-text-3 hover:text-text-2',
              )}
            >
              <Ico name={m.icon} />
            </SegmentedControlItem>
          );
        })}
      </SegmentedControl>
    </span>
  );
}

/**
 * Dashed 'no data' placeholder shown wherever an inventory list/section is empty
 * (nav groups, harness categories, the right pane), so empty state reads as
 * intentional rather than a blank gap.
 */
export function EmptyState({
  message,
  icon = 'list',
  className,
}: {
  message: string;
  icon?: IconName;
  className?: string | undefined;
}) {
  return (
    <div
      className={cn(
        'flex items-center gap-2.5 rounded-lg border border-dashed border-border-strong px-3 py-3.5 text-text-3',
        className,
      )}
    >
      <Ico name={icon} className="size-4 shrink-0" />
      <span className="text-xs">{message}</span>
    </div>
  );
}

/** Section header + body used across the inventory detail panes. */
export function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-label font-semibold uppercase tracking-wider text-text-3">
        {label}
      </div>
      {children}
    </div>
  );
}

export interface RadioCardMeta {
  label: string;
  desc: string;
  icon: IconName;
  fg: string;
  bg: string;
}
/**
 * A vertical list of selectable radio cards (icon tile · title · description ·
 * check). Used for both the per-file LLM-access picker and the MCP trust picker;
 * `accentOf` supplies the selected check-circle fill from the concrete meta.
 */
export function RadioCardList<T extends string, M extends RadioCardMeta>({
  order,
  meta,
  value,
  onChange,
  accentOf,
  refusal,
}: {
  order: T[];
  meta: Record<T, M>;
  value: T;
  onChange: (v: T) => void;
  accentOf: (m: M) => string;
  /**
   * Set when this whole list cannot be operated by the host: every option
   * renders offered-and-disabled via `refusedControlProps` (focusable,
   * `aria-disabled`, described by the one visible reason below), and
   * `onChange` is never called. Absent ⇒ identical to today. Shared by
   * FileDetailDrawer's access picker and AssetDetail's trust picker — both
   * lists carry exactly one value and one reason, never a per-option one
   * (contrast PolicyPicker.tsx's per-option `unavailable`, which this is
   * not).
   */
  refusal?: { id: string; reason: string } | undefined;
}) {
  const refused = refusal ? refusedControlProps(refusal.id, refusal.reason, '') : null;
  return (
    <div className="flex flex-col gap-2">
      {order.map((k) => {
        const m = meta[k];
        const on = k === value;
        return (
          <button
            key={k}
            type="button"
            onClick={
              refused
                ? undefined
                : () => {
                    onChange(k);
                  }
            }
            {...refused}
            className={cn(
              'flex items-center gap-3 rounded-lg border px-3 py-2.5 text-left cursor-pointer',
              on ? cn(m.bg, 'border-current', m.fg) : 'border-border bg-surface',
              refused?.className,
            )}
          >
            <span
              className={cn(
                'grid size-8 shrink-0 place-items-center rounded-lg',
                on ? 'bg-surface' : 'bg-surface-2',
                m.fg,
              )}
            >
              <Ico name={m.icon} className="size-4.5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className={cn('text-sm font-semibold', on ? m.fg : 'text-text')}>{m.label}</div>
              <div className="mt-0.5 text-xs text-text-2">{m.desc}</div>
            </div>
            <span
              className={cn(
                'grid size-4.5 shrink-0 place-items-center rounded-full border-[1.5px]',
                on ? cn('border-current text-on-accent', accentOf(m)) : 'border-border-strong',
              )}
            >
              {on && <Ico name="check" className="size-3" />}
            </span>
          </button>
        );
      })}
      {refusal && (
        <RefusalReason id={refusal.id} dataSlot="radio-card-list-refusal-reason">
          {refusal.reason}
        </RefusalReason>
      )}
    </div>
  );
}

export function AccessControl({
  value,
  onChange,
  refusal,
}: {
  value: AccessLevel;
  onChange: (v: AccessLevel) => void;
  /**
   * Set when this file's access control cannot be operated by the host:
   * renders as a single inert control at the current level via
   * `refusedControlProps`, in place of the live segmented toggle, and
   * `onChange` is never referenced. Absent ⇒ identical to today.
   *
   * Not passed down INTO the toggle: `SegmentedControl`'s own `disabled`
   * prop forwards to Radix `ToggleGroupPrimitive.Root`, which renders each
   * item with the native HTML `disabled` attribute — out of the tab order,
   * which is exactly what an offered-and-disabled control must not be (see
   * shared/Refusal.tsx). So a refused control is a different, single
   * element, not the same toggle with a prop flipped.
   */
  refusal?: { id: string; reason: string } | undefined;
}) {
  if (refusal) {
    const m = ACCESS[value];
    const refused = refusedControlProps(refusal.id, refusal.reason, '');
    return (
      // Matches IconToggle's own wrapper: stops a toggle click from also
      // selecting the row this control sits in.
      <span
        className="inline-flex"
        onClick={(e) => {
          e.stopPropagation();
        }}
      >
        <button
          type="button"
          data-slot="access-control"
          aria-label={`LLM access: ${m.label}`}
          {...refused}
          className={cn(
            'inline-flex size-7 items-center justify-center rounded-lg',
            m.fg,
            m.bg,
            refused.className,
          )}
        >
          <Ico name={m.icon} />
        </button>
      </span>
    );
  }
  return <IconToggle order={ACCESS_ORDER} meta={ACCESS} value={value} onChange={onChange} />;
}

export function AccessLabel({ value }: { value: AccessLevel }) {
  return (
    <span className={cn('min-w-23 whitespace-nowrap text-xs font-semibold', ACCESS[value].fg)}>
      {ACCESS[value].label}
    </span>
  );
}

/** Stacked horizontal bar showing the open/approved/blocked split. */
export function AccessBar({ counts, className }: { counts: AccessCounts; className?: string }) {
  const total = counts.total || 1;
  return (
    <span className={cn('flex h-1.5 w-30 overflow-hidden rounded-full bg-surface-3', className)}>
      {ACCESS_ORDER.map((k) => {
        const w = (counts[k] / total) * 100;
        return w > 0 ? (
          <span key={k} className={ACCESS[k].bar} style={{ width: `${String(w)}%` }} />
        ) : null;
      })}
    </span>
  );
}

export function TrustPill({ value }: { value: TrustLevel }) {
  const t = TRUST[value];
  return (
    <Badge variant={t.tone}>
      <Ico name={t.icon} className="size-3" />
      {t.label}
    </Badge>
  );
}

export function FlagChip({ flag, mini }: { flag: Flag; mini?: boolean | undefined }) {
  const f = FLAG[flag];
  return (
    <Badge variant={f.tone}>
      <Ico name={f.icon} className={mini ? 'size-2.5' : 'size-3'} />
      {mini ? f.short : f.label}
    </Badge>
  );
}

export function FlagChips({ flags, mini }: { flags: Flag[]; mini?: boolean | undefined }) {
  if (flags.length === 0) {
    if (mini) return null;
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ok-ink">
        <Ico name="check-circle" className="size-3.5" /> OK
      </span>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {flags.map((k) => (
        <FlagChip key={k} flag={k} mini={mini} />
      ))}
    </span>
  );
}

export function VisBadge({ v }: { v: Visibility }) {
  return v === 'public' ? (
    <Badge variant="success">
      <Ico name="globe" className="size-3" /> Public
    </Badge>
  ) : (
    <Badge variant="default">
      <Ico name="lock" className="size-3" /> Private
    </Badge>
  );
}

export function OriginTag({ origin }: { origin: Origin }) {
  const m = originMeta[origin];
  return (
    <Badge variant="default">
      <Ico name={m.icon} className="size-3" /> {m.short}
    </Badge>
  );
}
