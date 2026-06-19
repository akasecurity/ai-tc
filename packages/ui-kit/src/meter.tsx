import { cn } from './lib/cn.ts';

export interface MeterProps {
  value: number;
  max: number;
  /** Bar fill color — a CSS color string (e.g. a `var(--color-…)` token). */
  color: string;
  /** Track height in pixels. */
  height?: number;
  className?: string;
}

/** A horizontal progress/coverage bar. Clamps the fill to the [0, max] range. */
export function Meter({ value, max, color, height = 8, className }: MeterProps) {
  const clamped = Math.min(max, Math.max(0, value));
  const pct = max > 0 ? (clamped / max) * 100 : 0;
  return (
    <span
      role="meter"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={max}
      className={cn('block flex-1 overflow-hidden rounded-full bg-surface-3', className)}
      style={{ height }}
    >
      <span
        className="block h-full rounded-full"
        style={{ width: `${String(pct)}%`, background: color }}
      />
    </span>
  );
}
