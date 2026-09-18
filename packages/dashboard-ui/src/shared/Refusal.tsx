// The "offered-and-disabled" contract for a control this host cannot
// currently operate: `aria-disabled` rather than native `disabled` (which
// would drop the control from the tab order and hide its own `title`), a
// `title` for a pointer user, and `aria-describedby` pointing at a VISIBLE
// reason line — a tooltip alone is invisible on touch and unreliable for
// assistive tech. PolicyPicker's per-option `unavailable` state and this
// pane's own enable/disable Switch (DetectionDetailView.tsx) already spell
// this same shape out by hand; migrating them to share it is a follow-up, not
// done here, so as not to touch either's already-covered behavior in the same
// change that introduces the third and fourth caller.
import { cn } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

/**
 * The props a refused control spreads onto itself.
 *
 * `neutralizeHover` is required rather than defaulted: a `Button`'s hover
 * classes come from its `variant`/`tone` compound (see ui-kit's button.tsx)
 * and differ per combination — `outline`/`neutral` hovers via `bg-surface-2`,
 * `ghost`/`neutral` via `bg-surface-2` and `text-text`, and so on — so there
 * is no one override that cancels every combination. Each call site supplies
 * the exact utility that cancels ITS OWN hover state, or a refused control
 * would still light up under the pointer while inert.
 */
export function refusedControlProps(
  reasonId: string,
  reason: string,
  neutralizeHover: string,
): {
  'aria-disabled': true;
  'aria-describedby': string;
  title: string;
  className: string;
} {
  return {
    'aria-disabled': true,
    'aria-describedby': reasonId,
    title: reason,
    className: cn('cursor-not-allowed opacity-50', neutralizeHover),
  };
}

/**
 * The visible reason a refused control's `aria-describedby` points at —
 * same shape as PolicyPicker's `data-slot="policy-unavailable-reason"` line
 * and this pane's own `data-slot="enabled-locked-reason"` one.
 */
export function RefusalReason({
  id,
  dataSlot,
  className,
  children,
}: {
  id: string;
  dataSlot: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <p id={id} className={cn('text-xs text-text-3', className)} data-slot={dataSlot}>
      {children}
    </p>
  );
}
