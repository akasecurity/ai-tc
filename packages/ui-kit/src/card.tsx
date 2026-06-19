import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * Composable card primitives. Compose instead of passing header props:
 *
 *   <Card>
 *     <CardHeader>
 *       <CardIcon className="bg-sev-critical-fill text-sev-critical"><Icon /></CardIcon>
 *       <CardHeading>
 *         <CardTitle>Open by severity</CardTitle>
 *         <CardDescription>131 findings</CardDescription>
 *       </CardHeading>
 *       <CardAction><button>View all</button></CardAction>
 *     </CardHeader>
 *     <CardContent>…</CardContent>
 *   </Card>
 *
 * `CardIcon`, `CardHeading`, and `CardAction` are all optional.
 */
export function Card({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="card"
      className={cn('rounded-xl border border-border bg-surface', className)}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="card-header"
      className={cn('flex items-center gap-3 px-5 pt-5', className)}
      {...props}
    />
  );
}

/** Tinted square that holds a leading icon. Override the tile color via className. */
export function CardIcon({ className, ...props }: ComponentPropsWithRef<'span'>) {
  return (
    <span
      data-slot="card-icon"
      className={cn(
        'flex size-7.5 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-text-2',
        className,
      )}
      {...props}
    />
  );
}

/** Wrapper that stacks the title and description in the header's middle column. */
export function CardHeading({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return <div data-slot="card-heading" className={cn('min-w-0', className)} {...props} />;
}

export function CardTitle({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="card-title"
      className={cn('text-sm font-semibold text-text', className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div data-slot="card-description" className={cn('text-xs text-text-3', className)} {...props} />
  );
}

/** Element pinned to the right of the header (legend, link, menu). */
export function CardAction({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="card-action"
      className={cn('ml-auto flex items-center', className)}
      {...props}
    />
  );
}

/** Padded card body. Override the padding via className when needed. */
export function CardContent({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return <div data-slot="card-content" className={cn('p-5', className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="card-footer"
      className={cn('flex items-center border-t border-border px-5 py-3.5', className)}
      {...props}
    />
  );
}
