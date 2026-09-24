import * as DialogPrimitive from '@radix-ui/react-dialog';
import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * Modal dialog built on @radix-ui/react-dialog — portalled, with overlay,
 * focus trap, and escape/outside-click dismissal. Compound API:
 *
 *   <Dialog open={open} onOpenChange={setOpen}>
 *     <DialogContent className="w-[600px]">
 *       <DialogHeader>
 *         <DialogTitle>Title</DialogTitle>
 *         <DialogDescription>Subtitle</DialogDescription>
 *       </DialogHeader>
 *       <DialogBody>…body…</DialogBody>
 *       <DialogFooter>
 *         <DialogClose asChild><Button>Cancel</Button></DialogClose>
 *       </DialogFooter>
 *     </DialogContent>
 *   </Dialog>
 */
export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export type DialogContentProps = ComponentPropsWithRef<typeof DialogPrimitive.Content>;

export function DialogContent({ className, children, ...props }: DialogContentProps) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        data-slot="dialog-overlay"
        className="fixed inset-0 z-50 bg-ink/40"
      />
      <DialogPrimitive.Content
        data-slot="dialog-content"
        className={cn(
          'fixed left-1/2 top-1/2 z-50 flex max-h-[92vh] w-full max-w-lg -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-2xl border border-border bg-surface shadow-lg outline-none',
          className,
        )}
        {...props}
      >
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function DialogHeader({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="dialog-header"
      className={cn('flex shrink-0 flex-col gap-1 border-b border-border px-5 py-4', className)}
      {...props}
    />
  );
}

/**
 * The scrollable middle section between DialogHeader and DialogFooter. Carries
 * the same px-5 inset as the header/footer (DialogContent itself is padding-less),
 * a default gap between children, and takes the remaining height so long bodies
 * scroll while the header/footer stay pinned. Without it, raw children placed
 * directly in DialogContent render edge-to-edge with no vertical rhythm.
 */
export function DialogBody({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="dialog-body"
      className={cn('flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-5 py-4', className)}
      {...props}
    />
  );
}

export function DialogTitle({
  className,
  ...props
}: ComponentPropsWithRef<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      className={cn('font-display text-base font-semibold text-text', className)}
      {...props}
    />
  );
}

export function DialogDescription({
  className,
  ...props
}: ComponentPropsWithRef<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn('text-xs text-text-3', className)}
      {...props}
    />
  );
}

/**
 * The action row at the foot of a dialog. Right-aligned, which is the part a
 * caller should not have to remember: this carried no `justify` and so laid its
 * buttons out from the LEFT edge, and every consumer wanted the other thing —
 * some said so with a `justify-end`, others with a `<span className="flex-1" />`
 * spacer, and the ones that said nothing simply shipped left-aligned.
 *
 * A caller that genuinely wants another arrangement still passes its own
 * `justify-*`, which `cn` resolves in its favour. A footer that stacks rows
 * (`flex-col`) is the case to watch: `justify-end` then pushes content to the
 * BOTTOM rather than the right, so those pass `justify-start` here and align
 * their own action row instead.
 */
export function DialogFooter({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="dialog-footer"
      className={cn(
        'flex shrink-0 items-center justify-end gap-2.5 border-t border-border px-5 py-3.5',
        className,
      )}
      {...props}
    />
  );
}
