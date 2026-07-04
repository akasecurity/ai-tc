import type { EnforcementAction } from '@akasecurity/schema';
import { Card, CardContent, Skeleton } from '@akasecurity/ui-kit';

import { ArrowDownIcon, ArrowUpIcon } from '../shared/icons.tsx';
import { ENFORCEMENT_META } from './meta.ts';
import { numberFormat, WidgetEmpty, WidgetError } from './widget-shared.tsx';

// `actions` is expected pre-normalized to display order (zero-filled).
export interface EnforcementActionsView {
  total: number;
  actions: EnforcementAction[];
  isLoading: boolean;
  error: string | null;
}

export function EnforcementCardView({
  total,
  actions,
  isLoading,
  error,
  rangeLabel,
}: EnforcementActionsView & { rangeLabel: string }) {
  return (
    <Card className="flex flex-col shadow-sm">
      <CardContent aria-busy={isLoading} className="flex flex-1 flex-col justify-center gap-4">
        <div className="flex justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-text">Enforcement actions</div>
            <div className="mt-0.5 text-xs text-text-3">All users · {rangeLabel.toLowerCase()}</div>
          </div>
          <div className="text-right">
            {isLoading ? (
              <Skeleton className="ml-auto h-5 w-12" />
            ) : (
              <div className="font-display text-xl font-semibold leading-none text-text">
                {error ? '—' : numberFormat.format(total)}
              </div>
            )}
            <div className="mt-0.5 text-label text-text-3">total intercepted</div>
          </div>
        </div>
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          <div className="flex gap-3">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-20 flex-1" />
            ))}
          </div>
        ) : total === 0 ? (
          <WidgetEmpty message="No enforcement actions in this range." />
        ) : (
          <div className="flex gap-3">
            {actions.map((a) => {
              const meta = ENFORCEMENT_META[a.kind];
              const Icon = meta.icon;
              const up = a.delta > 0;
              return (
                <div
                  key={a.kind}
                  className="min-w-0 flex-1 border-l-[3px] pl-3"
                  style={{ borderColor: meta.color }}
                >
                  <div className="inline-flex items-center gap-1.5" style={{ color: meta.color }}>
                    <Icon aria-hidden focusable={false} className="size-4" />
                    <span className="text-xs font-semibold text-text-2">{meta.label}</span>
                  </div>
                  <div className="mt-2 font-display text-3xl font-semibold leading-none text-text">
                    {numberFormat.format(a.count)}
                  </div>
                  {a.delta !== 0 && (
                    // Direction (arrow + sign) conveys the change; color stays neutral
                    // because a drop in enforcement counts isn't unambiguously "good".
                    <div className="mt-1 inline-flex items-center gap-0.5 text-xs font-semibold text-text-3">
                      {up ? (
                        <ArrowUpIcon aria-hidden focusable={false} className="size-3" />
                      ) : (
                        <ArrowDownIcon aria-hidden focusable={false} className="size-3" />
                      )}
                      {up ? '+' : '−'}
                      {numberFormat.format(Math.abs(a.delta))} wk/wk
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
