import type { ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

export interface MeterProps extends ComponentPropsWithRef<'span'> {
  value: number;
  max: number;
  /** Bar fill color — a CSS color string (e.g. a `var(--color-…)` token). */
  color: string;
  /** Track height in pixels. */
  height?: number;
}

/** A horizontal progress/coverage bar. Clamps the fill to the [0, max] range. */
export function Meter({ value, max, color, height = 8, className, style, ...props }: MeterProps) {
  const clamped = Math.min(max, Math.max(0, value));
  const pct = max > 0 ? (clamped / max) * 100 : 0;
  return (
    <span
      data-slot="meter"
      role="meter"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={max}
      className={cn('block flex-1 overflow-hidden rounded-full bg-surface-3', className)}
      style={{ height, ...style }}
      {...props}
    >
      <span
        className="block h-full rounded-full"
        style={{ width: `${String(pct)}%`, background: color }}
      />
    </span>
  );
}
