// The Activity summary strip: one Card with inline stats separated by dividers.
import { Card, cn } from '@akasecurity/ui-kit';
import { Fragment } from 'react';

import type { IconComponent } from '../lib/icons.ts';

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

export function ActivitySummaryStripView({ items }: { items: SummaryStatItem[] }) {
  return (
    <Card className="mb-3.5 flex shrink-0 items-stretch py-3.5 shadow-sm">
      {items.map((item, i) => (
        <Fragment key={item.label}>
          {i > 0 && <span className="w-px shrink-0 self-stretch bg-text/6" />}
          <SummaryStat {...item} />
        </Fragment>
      ))}
    </Card>
  );
}
