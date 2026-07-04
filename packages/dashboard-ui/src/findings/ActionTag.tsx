import type { FindingAction } from '@akasecurity/schema';
import { cn, Tag } from '@akasecurity/ui-kit';

import { LayersIcon } from '../shared/icons.tsx';
import { ACTION_META } from './meta.ts';

// A colored status pill — Tag's neutral border/surface is overridden via cn so it
// reads as a severity-tinted action chip rather than a plain metadata label.
const PILL = 'rounded-full border-transparent px-2.5 text-xs [&_svg]:size-3.5';

export function ActionTag({ action }: { action: FindingAction }) {
  const meta = ACTION_META[action];
  const Icon = meta.icon;
  return (
    <Tag icon={<Icon />} className={cn(PILL, meta.className)}>
      {meta.label}
    </Tag>
  );
}

/**
 * Shows the group's shared action, or a neutral "Mixed" tag when its locations
 * disagree (the findings response sends `aggregateAction: null` in that case).
 */
export function AggregateActionTag({ aggregateAction }: { aggregateAction: FindingAction | null }) {
  if (aggregateAction) return <ActionTag action={aggregateAction} />;
  return (
    <Tag icon={<LayersIcon />} className={cn(PILL, 'bg-surface-3 text-text-2')}>
      Mixed
    </Tag>
  );
}
