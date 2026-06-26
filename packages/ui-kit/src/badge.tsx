import { cva, type VariantProps } from 'class-variance-authority';
import type { ReactNode } from 'react';

import { cn } from './lib/cn.ts';

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold',
  {
    variants: {
      variant: {
        default: 'bg-surface-3 text-text-2',
        outline: 'border border-border text-text-2',
        critical: 'bg-sev-critical-fill text-sev-critical',
        high: 'bg-sev-high-fill text-sev-high',
        medium: 'bg-sev-medium-fill text-sev-medium',
        low: 'bg-sev-low-fill text-sev-low',
        // Tonal (non-severity) variants for status/category chips.
        success: 'bg-ok-fill text-ok',
        teal: 'bg-teal-fill text-teal',
        info: 'bg-sev-low-fill text-sev-low',
        primary: 'bg-primary-tint text-primary',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface BadgeProps extends VariantProps<typeof badgeVariants> {
  children: ReactNode;
  className?: string;
}

export function Badge({ variant, className, children }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)}>{children}</span>;
}

const DOT_CLASS: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
};

/** A severity pill with a leading status dot — capitalizes the label. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severity} className="h-6">
      <span className={cn('size-1.5 rounded-full', DOT_CLASS[severity])} />
      <span className="capitalize">{severity}</span>
    </Badge>
  );
}
