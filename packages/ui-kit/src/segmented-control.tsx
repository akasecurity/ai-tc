import * as ToggleGroupPrimitive from '@radix-ui/react-toggle-group';
import { type ComponentPropsWithRef, type ReactNode, type Ref } from 'react';

import { cn } from './lib/cn.ts';

/**
 * A single-select segmented control built on @radix-ui/react-toggle-group
 * (type="single"). Radix gives us roving-focus keyboard navigation and the
 * `data-state="on"` selected styling hook. Compound API:
 *
 *   <SegmentedControl value={mode} onValueChange={setMode}>
 *     <SegmentedControlItem value="a">A</SegmentedControlItem>
 *     <SegmentedControlItem value="b">B</SegmentedControlItem>
 *   </SegmentedControl>
 *
 * `value` is intentionally non-nullable in practice: pass a controlled value and
 * ignore empty deselects in the handler if you need a permanently-selected segment.
 *
 * Props are pinned to the single-select shape (rather than Radix's value union)
 * so `value`/`onValueChange` stay plain strings for consumers.
 */
export interface SegmentedControlProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  disabled?: boolean;
  className?: string;
  children?: ReactNode;
  ref?: Ref<HTMLDivElement>;
}

export function SegmentedControl({ className, ...props }: SegmentedControlProps) {
  return (
    <ToggleGroupPrimitive.Root
      type="single"
      data-slot="segmented-control"
      className={cn(
        'inline-flex items-center gap-0.5 rounded-lg border border-border bg-surface-2 p-0.5',
        className,
      )}
      {...props}
    />
  );
}

export type SegmentedControlItemProps = ComponentPropsWithRef<typeof ToggleGroupPrimitive.Item>;

export function SegmentedControlItem({ className, ...props }: SegmentedControlItemProps) {
  return (
    <ToggleGroupPrimitive.Item
      data-slot="segmented-control-item"
      className={cn(
        'inline-flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-text-3 transition-colors cursor-pointer',
        'hover:text-text-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        'data-[state=on]:bg-surface data-[state=on]:text-text data-[state=on]:shadow-sm',
        '[&_svg]:size-4 [&_svg]:shrink-0',
        className,
      )}
      {...props}
    />
  );
}
