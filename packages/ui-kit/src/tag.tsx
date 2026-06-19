import { type ReactNode } from 'react';

import { cn } from './lib/cn.ts';

export interface TagProps {
  children: ReactNode;
  /** Optional leading icon element. */
  icon?: ReactNode;
  /** Optional colored status dot (a CSS color string). */
  dot?: string;
  className?: string;
}

/**
 * A small neutral chip for metadata labels (e.g. repo / policy names).
 * Distinct from `Badge`, which conveys count/severity.
 */
export function Tag({ children, icon, dot, className }: TagProps) {
  return (
    <span
      className={cn(
        'inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-md border border-border bg-surface px-2 text-label font-medium text-text-2',
        className,
      )}
    >
      {dot && <span className="size-1.5 shrink-0 rounded-full" style={{ background: dot }} />}
      {icon}
      {children}
    </span>
  );
}
