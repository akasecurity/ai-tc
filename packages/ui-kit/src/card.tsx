import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';
import { type Tone, TONE_SOFT } from './tone.ts';

/**
 * Composable card primitives. Compose instead of passing header props:
 *
 *   <Card>
 *     <CardHeader>
 *       <CardIcon tone="critical"><Icon /></CardIcon>
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

/**
 * Tinted square that holds a leading icon. `tone` names the tonal family and
 * defaults to `neutral`, the tile's own surface.
 *
 * Prefer it over spelling the fill/ink pair into `className`: the pairing is
 * irregular (primary's tint is `-tint`, and its bare token is already the ink),
 * and getting it wrong fails silently — an undefined theme variable emits no
 * utility, so the glyph just inherits its color. `className` still wins, for the
 * one-off tile whose color is not a family theme.css names.
 */
export function CardIcon({
  className,
  tone = 'neutral',
  ...props
}: ComponentPropsWithRef<'span'> & { tone?: Tone }) {
  return (
    <span
      data-slot="card-icon"
      className={cn(
        'flex size-7.5 shrink-0 items-center justify-center rounded-lg',
        TONE_SOFT[tone],
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
