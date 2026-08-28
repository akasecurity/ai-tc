import { cva, type VariantProps } from 'class-variance-authority';
import type { ReactNode } from 'react';

import { cn } from './lib/cn.ts';
import { TONE_SOFT } from './tone.ts';

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold',
  {
    variants: {
      variant: {
        // `default` is the one tonal variant with no TONE_SOFT member: the
        // vocabulary's `neutral` is bg-surface-2, and this is the step deeper.
        default: 'bg-surface-3 text-text-2',
        outline: 'border border-border text-text-2',
        // The rest ARE vocabulary members, so they are read from it rather than
        // respelled — a second copy of a pair is a second place to get the
        // fill/ink halves wrong, which is the failure tone.ts exists to remove.
        // The variant NAMES stay as they are: `variant` is public API, and
        // `success` is spelled across consumers outside this repo.
        critical: TONE_SOFT.critical,
        high: TONE_SOFT.high,
        medium: TONE_SOFT.medium,
        low: TONE_SOFT.low,
        success: TONE_SOFT.ok,
        teal: TONE_SOFT.teal,
        primary: TONE_SOFT.primary,
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
