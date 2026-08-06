// The Activity summary strip: one Card with inline stats separated by dividers.
import { Card, cn, Skeleton } from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { WidgetError } from '../shared/widget-state.tsx';

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
// the strip is chrome above the session list, so its height is space the list
// does not get, and a label long enough to wrap is truncated with the full text
// on hover rather than growing the row.
function SummaryStat({ icon: Icon, value, label, text, fill }: SummaryStatItem) {
  return (
    <div className="flex min-w-0 flex-1 items-center gap-2 px-4">
      <span className={cn('grid size-7 shrink-0 place-items-center rounded-lg', fill, text)}>
        <Icon aria-hidden focusable={false} className="size-3.5" />
      </span>
      <div className="flex min-w-0 items-baseline gap-1.5" title={`${String(value)} ${label}`}>
        <span className="font-display text-lg font-semibold leading-none tabular-nums text-text">
          {value}
        </span>
        <span className="truncate text-xs text-text-3">{label}</span>
      </div>
    </div>
  );
}

export function ActivitySummaryStripView({
  items,
  isLoading,
  error,
}: {
  items: SummaryStatItem[];
  isLoading: boolean;
  error: string | null;
}) {
  return (
    <Card className="mb-3 flex shrink-0 items-stretch py-2.5 shadow-sm" aria-busy={isLoading}>
      {error ? (
        <div className="px-5">
          <WidgetError message={error} />
        </div>
      ) : isLoading && items.length === 0 ? (
        Array.from({ length: 5 }, (_, i) => (
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
