'use client';

// Small shared presentational pieces for the Inventory page: the empty state,
// section headings, the MCP trust picker, status chips and the back button.
import type { Flag, TrustLevel } from '@akasecurity/schema';
import { Badge, Button, cn } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import { RefusalReason, refusedControlProps } from '../shared/Refusal.tsx';
import { FLAG, TRUST } from './data.ts';
import { Ico } from './Ico.tsx';
import { type IconName } from './icons.ts';

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
 * check), used for the MCP trust picker. `accentOf` supplies the selected
 * check-circle fill from the concrete meta.
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
   * `onChange` is never called. One reason covers the whole list, never a
   * per-option one.
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

/** The icon-only back button the details pages lead with. */
export function BackButton({ onBack, backLabel }: { onBack: () => void; backLabel: string }) {
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={`Back to ${backLabel}`}
      title={`Back to ${backLabel}`}
      onClick={onBack}
      className="-ml-2 shrink-0"
    >
      <Ico name="chevron-left" />
    </Button>
  );
}

/** A details pane with nothing to show yet (loading, failed, gone), keeping the way back. */
export function DetailFallback({
  message,
  onBack,
  backLabel,
}: {
  message: string;
  onBack: () => void;
  backLabel: string;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center border-b border-border px-5 py-3.5">
        <BackButton onBack={onBack} backLabel={backLabel} />
      </div>
      <div className="grid min-h-0 flex-1 place-items-center p-8 text-center text-sm text-text-3">
        {message}
      </div>
    </div>
  );
}
