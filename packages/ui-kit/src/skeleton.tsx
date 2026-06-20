import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * Presentational loading placeholder. Purely visual (no focus/positioning
 * concerns), so it has no Radix counterpart — it's a plain animated `div`.
 * Size it via `className` (e.g. `className="h-4 w-24"`).
 */
export function Skeleton({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="skeleton"
      className={cn('animate-pulse rounded-md bg-surface-3', className)}
      {...props}
    />
  );
}
