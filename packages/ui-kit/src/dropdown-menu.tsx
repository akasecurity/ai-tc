import * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu';
import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/** Inline checkmark — keeps ui-kit free of an external icon dependency. */
function CheckMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" fill="none" aria-hidden focusable={false} className={className}>
      <path
        d="M13 4.5 6.5 11 3 7.5"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * Menu built on @radix-ui/react-dropdown-menu — portalled, keyboard-navigable
 * (arrow keys, typeahead), with proper `menuitem`/`menuitemradio` semantics.
 *
 *   <DropdownMenu>
 *     <DropdownMenuTrigger asChild><Button>Open</Button></DropdownMenuTrigger>
 *     <DropdownMenuContent align="end">
 *       <DropdownMenuRadioGroup value={v} onValueChange={setV}>
 *         <DropdownMenuRadioItem value="a">A</DropdownMenuRadioItem>
 *       </DropdownMenuRadioGroup>
 *     </DropdownMenuContent>
 *   </DropdownMenu>
 */
export const DropdownMenu = DropdownMenuPrimitive.Root;
export const DropdownMenuTrigger = DropdownMenuPrimitive.Trigger;
export const DropdownMenuGroup = DropdownMenuPrimitive.Group;
export const DropdownMenuRadioGroup = DropdownMenuPrimitive.RadioGroup;
export const DropdownMenuItemIndicator = DropdownMenuPrimitive.ItemIndicator;

const itemClass =
  'flex cursor-pointer select-none items-center gap-2 rounded-md px-2.5 py-1.5 text-sm text-text-2 outline-none focus:bg-surface-2 focus:text-text data-[disabled]:pointer-events-none data-[disabled]:opacity-50';

export function DropdownMenuContent({
  className,
  sideOffset = 6,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.Content>) {
  return (
    <DropdownMenuPrimitive.Portal>
      <DropdownMenuPrimitive.Content
        sideOffset={sideOffset}
        className={cn(
          'z-50 min-w-32 overflow-hidden rounded-lg border border-border bg-surface p-1 shadow-lg',
          className,
        )}
        {...props}
      />
    </DropdownMenuPrimitive.Portal>
  );
}

export function DropdownMenuItem({
  className,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.Item>) {
  return <DropdownMenuPrimitive.Item className={cn(itemClass, className)} {...props} />;
}

export function DropdownMenuRadioItem({
  className,
  children,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.RadioItem>) {
  return (
    <DropdownMenuPrimitive.RadioItem
      className={cn(
        itemClass,
        'data-[state=checked]:font-semibold data-[state=checked]:text-text',
        className,
      )}
      {...props}
    >
      <span className="flex-1">{children}</span>
      <DropdownMenuPrimitive.ItemIndicator>
        <CheckMark className="size-4 text-primary" />
      </DropdownMenuPrimitive.ItemIndicator>
    </DropdownMenuPrimitive.RadioItem>
  );
}

/**
 * A multi-select menu item with a leading checkbox box. Radix closes the menu on
 * select by default — for a multi-select filter, call `e.preventDefault()` in
 * `onSelect` so the menu stays open across toggles.
 */
export function DropdownMenuCheckboxItem({
  className,
  children,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.CheckboxItem>) {
  return (
    <DropdownMenuPrimitive.CheckboxItem
      className={cn(
        itemClass,
        'group data-[state=checked]:font-semibold data-[state=checked]:text-text',
        className,
      )}
      {...props}
    >
      <span className="grid size-4 shrink-0 place-items-center rounded-[5px] border border-border-strong text-text-inv transition-colors group-data-[state=checked]:border-primary group-data-[state=checked]:bg-primary">
        <DropdownMenuPrimitive.ItemIndicator>
          <CheckMark className="size-3" />
        </DropdownMenuPrimitive.ItemIndicator>
      </span>
      <span className="flex-1">{children}</span>
    </DropdownMenuPrimitive.CheckboxItem>
  );
}

export function DropdownMenuLabel({
  className,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.Label>) {
  return (
    <DropdownMenuPrimitive.Label
      className={cn(
        'px-2.5 py-1.5 text-label font-semibold uppercase tracking-wider text-text-3',
        className,
      )}
      {...props}
    />
  );
}

export function DropdownMenuSeparator({
  className,
  ...props
}: ComponentPropsWithRef<typeof DropdownMenuPrimitive.Separator>) {
  return (
    <DropdownMenuPrimitive.Separator
      className={cn('-mx-1 my-1 h-px bg-border', className)}
      {...props}
    />
  );
}
