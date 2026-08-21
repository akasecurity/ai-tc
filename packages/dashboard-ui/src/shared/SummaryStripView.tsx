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

export interface SummaryStatItem {
  icon: IconComponent;
  value: string | number;
  label: string;
  /** icon foreground token class, e.g. `text-ok-ink`. */
  text: string;
  /** icon tile fill token class, e.g. `bg-ok-fill`. */
  fill: string;
}

// One stat. The value and its label sit on a single baseline rather than stacked:
// the strip is chrome above a list, so its height is space that list does not
// get, and a label long enough to wrap is truncated with the full text on hover
// rather than growing the row.
function SummaryStat({ icon: Icon, value, label, text, fill }: SummaryStatItem) {
  return (
    <div className="flex min-w-0 flex-1 items-center gap-2 px-4">
      <span className={cn('grid size-7 shrink-0 place-items-center rounded-lg', fill, text)}>
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      <div className="flex min-w-0 items-baseline gap-1.5" title={`${String(value)} ${label}`}>
        {/* The value never wraps: a value carrying a space (Detections' "7 / 7")
            has a one-character min-content width, so flex shrink would break it
            across lines and grow the whole Card past the one row its height is
            declared to be. The label beside it truncates instead — it is the
            half that has a hover fallback. */}
        <span className="whitespace-nowrap font-display text-lg font-semibold leading-none tabular-nums text-text">
          {value}
        </span>
        <span className="truncate text-xs text-text-3">{label}</span>
      </div>
    </div>
  );
}

export function SummaryStripView({
  items,
  isLoading,
  error,
  placeholderCount = 5,
  className,
}: {
  items: SummaryStatItem[];
  isLoading: boolean;
  error: string | null;
  /**
   * How many placeholder cells the loading state draws. Defaults to the five
   * Activity shows; a caller with a different stat count passes its own, so the
   * strip does not change width-per-cell on reveal.
   */
  placeholderCount?: number;
  /** Caller-owned spacing — the strip carries no margin of its own. */
  className?: string;
}) {
  return (
    <Card
      className={cn('flex shrink-0 items-stretch py-2.5 shadow-sm', className)}
      aria-busy={isLoading}
    >
      {error ? (
        <div className="px-5">
          <WidgetError message={error} />
        </div>
      ) : isLoading && items.length === 0 ? (
        Array.from({ length: placeholderCount }, (_, i) => (
          <Fragment key={i}>
            {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
            <div className="flex flex-1 items-center gap-2 px-4">
              <Skeleton className="size-7 shrink-0 rounded-lg" />
              <Skeleton className="h-4 w-24" />
            </div>
          </Fragment>
        ))
      ) : (
        items.map((item, i) => (
          <Fragment key={item.label}>
            {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
            <SummaryStat {...item} />
          </Fragment>
        ))
      )}
    </Card>
  );
}
