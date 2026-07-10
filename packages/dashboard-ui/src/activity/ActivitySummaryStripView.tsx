// The Activity summary strip: one Card with inline stats separated by dividers.
import { Card, cn, Skeleton } from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { WidgetError } from '../shared/widget-state.tsx';

export interface SummaryStatItem {
  icon: IconComponent;
  value: string | number;
  label: string;
  /** icon foreground token class, e.g. `text-ok`. */
  text: string;
  /** icon tile fill token class, e.g. `bg-ok-fill`. */
  fill: string;
}

function SummaryStat({ icon: Icon, value, label, text, fill }: SummaryStatItem) {
  return (
    <div className="flex flex-1 items-center gap-2.5 px-5">
      <span className={cn('grid size-8 shrink-0 place-items-center rounded-lg', fill, text)}>
        <Icon aria-hidden focusable={false} className="size-4" />
      </span>
      <div className="min-w-0">
        <div className="font-display text-xl font-semibold leading-none tabular-nums text-text">
          {value}
        </div>
        <div className="mt-0.5 text-xs text-text-3">{label}</div>
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
    <Card className="mb-3.5 flex shrink-0 items-stretch py-3.5 shadow-sm" aria-busy={isLoading}>
      {error ? (
        <div className="px-5">
          <WidgetError message={error} />
        </div>
      ) : isLoading && items.length === 0 ? (
        Array.from({ length: 5 }, (_, i) => (
          <Fragment key={i}>
            {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
            <div className="flex flex-1 items-center gap-2.5 px-5">
              <Skeleton className="size-8 shrink-0 rounded-lg" />
              <div className="min-w-0 flex-1">
                <Skeleton className="h-5 w-10" />
                <Skeleton className="mt-1 h-3 w-20" />
              </div>
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
