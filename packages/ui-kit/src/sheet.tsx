import * as Dialog from '@radix-ui/react-dialog';
import type { ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * Slide-over panel built on @radix-ui/react-dialog — portalled, with overlay,
 * focus trap, and escape/outside-click dismissal. Anchored to the right edge.
 * Compound API mirrors Dialog:
 *
 *   <Sheet open={open} onOpenChange={setOpen}>
 *     <SheetContent>
 *       <SheetHeader>
 *         <SheetTitle>Title</SheetTitle>
 *         <SheetDescription>Subtitle</SheetDescription>
 *       </SheetHeader>
 *       …body…
 *     </SheetContent>
 *   </Sheet>
 */
export const Sheet = Dialog.Root;
export const SheetTrigger = Dialog.Trigger;
export const SheetClose = Dialog.Close;

export type SheetContentProps = ComponentPropsWithRef<typeof Dialog.Content>;

export function SheetContent({ className, children, ...props }: SheetContentProps) {
  return (
    <Dialog.Portal>
      <Dialog.Overlay
        data-slot="sheet-overlay"
        className="fixed inset-0 z-40 bg-ink/40 backdrop-blur-[1px]"
      />
      <Dialog.Content
        data-slot="sheet-content"
        className={cn(
          'fixed inset-y-0 right-0 z-50 flex h-full w-full max-w-md flex-col gap-4 overflow-y-auto border-l border-border bg-surface p-6 shadow-lg outline-none',
          className,
        )}
        {...props}
      >
        {children}
        <Dialog.Close className="absolute right-4 top-4 cursor-pointer rounded-md text-text-3 transition-colors hover:bg-surface-2 hover:text-text size-8 grid place-content-center">
          <svg
            aria-hidden
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.6}
            strokeLinecap="round"
            strokeLinejoin="round"
            className="size-4"
          >
            <path d="M6 6 18 18M18 6 6 18" />
          </svg>
          <span className="sr-only">Close</span>
        </Dialog.Close>
      </Dialog.Content>
    </Dialog.Portal>
  );
}

export function SheetHeader({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="sheet-header"
      className={cn('flex flex-col gap-1 pr-8', className)}
      {...props}
    />
  );
}

export function SheetTitle({ className, ...props }: ComponentPropsWithRef<typeof Dialog.Title>) {
  return (
    <Dialog.Title
      data-slot="sheet-title"
      className={cn('font-display text-lg font-semibold text-text', className)}
      {...props}
    />
  );
}

export function SheetDescription({
  className,
  ...props
}: ComponentPropsWithRef<typeof Dialog.Description>) {
  return (
    <Dialog.Description
      data-slot="sheet-description"
      className={cn('text-sm text-text-2', className)}
      {...props}
    />
  );
}
