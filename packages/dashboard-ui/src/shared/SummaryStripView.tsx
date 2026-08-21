// The compact summary strip: one Card with inline stats separated by dividers.
//
// It lives in shared/ rather than under one feature folder because Activity,
// Detections and Policies all head their master/detail with it. The strip is
// chrome above a list, so its whole point is to cost as little vertical space
// as a row of stats can: a stacked tile card measures 112px, this one 50px, and
// the difference is height the list underneath gets instead.
import { Card, cn, Skeleton } from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { WidgetError } from './widget-state.tsx';

/**
 * A stat's tonal family. Naming the family rather than its two class strings is
 * what stops the halves being crossed: a `-ink` foreground belongs to exactly
 * one `-fill` tint, and spelling both by hand at each call site compiles and
 * renders whichever pair is typed.
 */
export type StatTone = 'primary' | 'neutral' | 'violet' | 'ok' | 'critical' | 'teal';

// Annotated `Record<StatTone, …>` so a tone added to the union fails to compile
// until its pair is chosen here, rather than resolving to undefined at render.
const STAT_TONES: Record<StatTone, { text: string; fill: string }> = {
  primary: { text: 'text-primary', fill: 'bg-primary-tint' },
  neutral: { text: 'text-text-2', fill: 'bg-surface-2' },
  violet: { text: 'text-violet-ink', fill: 'bg-violet-fill' },
  ok: { text: 'text-ok-ink', fill: 'bg-ok-fill' },
  critical: { text: 'text-sev-critical-ink', fill: 'bg-sev-critical-fill' },
  teal: { text: 'text-teal-ink', fill: 'bg-teal-fill' },
};

export interface SummaryStatItem {
  icon: IconComponent;
  value: string | number;
  label: string;
  tone: StatTone;
}

// One stat. The value and its label sit on a single baseline rather than stacked:
// the strip is chrome above a list, so its height is space that list does not
// get, and a label long enough to wrap is truncated with the full text on hover
// rather than growing the row.
//
// While loading, the icon and label stay and only the VALUE is withheld. That is
// the half the read has not answered yet; withholding the label too would leave
// an anonymous grey bar that no longer says what is loading.
function SummaryStat({
  icon: Icon,
  value,
  label,
  tone,
  isLoading,
}: SummaryStatItem & { isLoading: boolean }) {
  const { text, fill } = STAT_TONES[tone];
  return (
    <div data-slot="summary-stat" className="flex min-w-0 flex-1 items-center gap-2 px-4">
      <span
        data-slot="summary-stat-icon"
        className={cn('grid size-7 shrink-0 place-items-center rounded-lg', fill, text)}
      >
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      {/* `overflow-hidden` bounds the pair to its own cell. The value below does
          not wrap and does not shrink, so without a clip here a value wider than
          its 1/n share would paint over the divider and the next cell's icon. */}
      <div
        className="flex min-w-0 items-baseline gap-1.5 overflow-hidden"
        title={isLoading ? label : `${String(value)} ${label}`}
      >
        {isLoading ? (
          <Skeleton className="h-4 w-10 shrink-0" />
        ) : (
          /* The value never wraps and never shrinks: a value carrying a space
             (Detections' "7 / 7") has a one-character min-content width, so flex
             shrink would break it across lines and grow the whole Card past the
             one row its height is declared to be. The label beside it absorbs
             the shrink instead — it is the half with a hover fallback. */
          <span className="shrink-0 whitespace-nowrap font-display text-lg font-semibold leading-none tabular-nums text-text">
            {value}
          </span>
        )}
        <span className="truncate text-xs text-text-3">{label}</span>
      </div>
    </div>
  );
}

export function SummaryStripView({
  items,
  isLoading,
  error,
  className,
}: {
  items: SummaryStatItem[];
  /**
   * Withholds each stat's VALUE while the read is in flight. The items are still
   * passed and still rendered, so the strip keeps saying what is loading and
   * cannot change its cell count — or its width-per-cell — on reveal.
   */
  isLoading: boolean;
  error: string | null;
  /** Caller-owned spacing — the strip carries no margin of its own. */
  className?: string | undefined;
}) {
  return (
    <Card
      className={cn('flex shrink-0 items-stretch overflow-hidden py-2.5 shadow-sm', className)}
      aria-busy={isLoading}
    >
      {error ? (
        <div className="px-5">
          <WidgetError message={error} />
        </div>
      ) : (
        items.map((item, i) => (
          <Fragment key={item.label}>
            {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
            <SummaryStat {...item} isLoading={isLoading} />
          </Fragment>
        ))
      )}
    </Card>
  );
}
