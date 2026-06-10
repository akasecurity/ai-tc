import type { ReactNode } from 'react';

interface BadgeProps {
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'default';
  children: ReactNode;
}

const VARIANT_CLASSES: Record<NonNullable<BadgeProps['variant']>, string> = {
  critical: 'badge badge--critical',
  high: 'badge badge--high',
  medium: 'badge badge--medium',
  low: 'badge badge--low',
  default: 'badge',
};

export function Badge({ variant = 'default', children }: BadgeProps) {
  return <span className={VARIANT_CLASSES[variant]}>{children}</span>;
}
