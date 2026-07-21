import { Card, cn, Skeleton } from '@akasecurity/ui-kit';

import { COLORS } from '../lib/colors.ts';
import type { IconComponent } from '../lib/icons.ts';
import { Sparkline } from './charts.tsx';
import { ArrowDownIcon, ArrowUpIcon } from './icons.tsx';

/**
 * Optional trend indicator shown to the right of a stat's value.
 * `tone` colors the text (semantic, not directional): a metric can rise and be
 * good (`positive`) or rise and be bad (`negative`). `dir` picks the arrow glyph;
 * omit it for a plain contextual figure (e.g. "12 teams").
 */
export interface StatDelta {
  label: string;
  tone?: 'positive' | 'negative' | 'neutral';
  dir?: 'up' | 'down';
}

function DeltaPill({ label, tone = 'neutral', dir }: StatDelta) {
  const toneClass =
    tone === 'positive' ? 'text-ok' : tone === 'negative' ? 'text-sev-critical' : 'text-text-3';
  const Arrow = dir === 'up' ? ArrowUpIcon : dir === 'down' ? ArrowDownIcon : null;
  return (
    <span className={cn('inline-flex items-center gap-1 text-xs font-semibold', toneClass)}>
      {Arrow && <Arrow aria-hidden focusable={false} className="size-3" />}
      {label}
    </span>
  );
}

/**
 * A stat tile: a tinted icon + label on top, with a large value below. Mirrors
 * the design's `.stat` card (18px padding, 34px icon tile, 30px display value).
 *
 * Pass `loading` to show a placeholder in place of the value while the figure is
 * being fetched — distinct from a settled-but-unknown value, which the caller
 * renders as its own `value` (e.g. an em dash on error). `delta` and `spark` are
 * optional; supply them for the richer KPI tiles on the Operations overview.
 */
export function StatTile({
  icon: Icon,
  iconBg,
  iconColor,
  label,
  value,
  delta,
  spark,
  sparkColor,
  sparkLabels,
  sparkFormatValue,
  loading = false,
}: {
  icon: IconComponent;
  iconBg: string;
  iconColor: string;
  label: string;
  value: string;
  delta?: StatDelta;
  spark?: number[];
  sparkColor?: string;
  /** Per-point hover labels for the sparkline tooltip (see Sparkline). */
  sparkLabels?: string[];
  /** Sparkline tooltip value formatter. */
  sparkFormatValue?: (v: number) => string;
  loading?: boolean;
}) {
  return (
    <Card className="flex flex-col gap-2.5 p-4.5 shadow-sm" aria-busy={loading || undefined}>
      <div className="flex items-center gap-2.5">
        <span
          className="grid size-8.5 shrink-0 place-items-center rounded-lg"
          style={{ background: iconBg, color: iconColor }}
        >
          <Icon aria-hidden focusable={false} className="size-4.5" />
        </span>
        <span className="text-ui font-medium text-text-2">{label}</span>
      </div>
      {loading ? (
        <Skeleton className="my-1 h-7 w-10" />
      ) : (
        <div className="flex items-end justify-between gap-2">
          <span className="font-display text-3xl font-semibold leading-none tracking-[-0.03em] text-text">
            {value}
          </span>
          {delta && <DeltaPill {...delta} />}
        </div>
      )}
      {spark && !loading && (
        <div className="mt-0.5">
          <Sparkline
            data={spark}
            color={sparkColor ?? COLORS.primary}
            height={34}
            {...(sparkLabels ? { labels: sparkLabels } : {})}
            {...(sparkFormatValue ? { formatValue: sparkFormatValue } : {})}
          />
        </div>
      )}
    </Card>
  );
}
