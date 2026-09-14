import { cva, type VariantProps } from 'class-variance-authority';
import type { ReactNode } from 'react';

import { cn } from './lib/cn.ts';
import { TONE_SOFT } from './tone.ts';

const badgeVariants = cva(
  'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-semibold',
  {
    variants: {
      variant: {
        // Every TINTED variant reads its pair from the vocabulary rather than
        // respelling it — a second copy of a pair is a second place to get the
        // fill/ink halves wrong, which is the failure tone.ts exists to remove.
        // `default` is `neutral`, the untinted pair; `outline` is the one variant
        // with no vocabulary member, because it carries no fill at all. The
        // variant NAMES stay as they are: `variant` is public API, and `success`
        // is spelled across consumers outside this repo.
        default: TONE_SOFT.neutral,
        outline: 'border border-border text-text-2',
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

/**
 * Severity → its dot's background token. Exported because more than one control
 * leads with this dot (the badge below, and the findings type filter's pills),
 * and a second copy of the map is a token rename away from generating no CSS at
 * all — an undefined theme variable produces no utility and the element simply
 * renders uncoloured, with nothing to catch it.
 */
export const SEVERITY_DOT_CLASS: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
};

/** A severity pill with a leading status dot — capitalizes the label. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severity} className="h-6">
      <span className={cn('size-1.5 rounded-full', SEVERITY_DOT_CLASS[severity])} />
      <span className="capitalize">{severity}</span>
    </Badge>
  );
}
