import type { ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * A text input primitive. Styles a native `<input>` with the design tokens
 * (surface fill, border, primary focus ring) so forms across the dashboards
 * share one field look. `ref` flows through as a regular prop (React 19).
 *
 * The fill is `bg-surface-2` and the edge is `border-border-field`, and the two
 * are one decision. Card, DialogContent and SheetContent are all `bg-surface`,
 * which is where forms live — so a `bg-surface` field had a fill identical to the
 * panel under it, leaving the border as the only thing marking the control. That
 * is the case `border-border` fails at 1.26:1, which is near-invisible to a
 * low-vision reader. `border-border-field` fixes the contrast half (3.20:1 on
 * this fill); `bg-surface-2` fixes the other half, so the control reads as a
 * field rather than an outline drawn on nothing.
 *
 * The fill step is deliberately slight — 1.05:1 light, 1.21:1 dark. It is a hint,
 * not a boundary: the border still does all the contrast work.
 *
 * `bg-surface-2` is not a free choice — theme.css annotates it `row hover /
 * subtle inset`, and it is also the menu-highlight fill (`select.tsx`'s
 * `data-[highlighted]`, `dropdown-menu.tsx`'s `focus:`). So a field now shares a
 * fill with a read-only inset box and with a highlighted menu row: the 1.05:1
 * gained against the panel is smaller than the 1.000:1 given up against those
 * state fills. That trade is deliberate — the panel is what a field must be
 * findable against, and the edge (3.20:1 here) is what separates it from an inset
 * box, which carries none. Do not read the paragraph above as covering a DISABLED
 * field: `disabled:opacity-50` collapses this fill step to 1.02:1 and the border
 * to 1.71:1.
 *
 * A field on the page CANVAS wants `bg-surface` instead — in light the canvas and
 * `--color-surface-2` are the same hex, so `bg-surface-2` there is the very
 * collision this fill exists to avoid. See the token's note in theme.css.
 */
export function Input({ className, type = 'text', ...props }: ComponentPropsWithRef<'input'>) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        'h-9 w-full rounded-lg border border-border-field bg-surface-2 px-3 text-sm text-text',
        'truncate placeholder:text-text-3 transition-colors',
        'focus:border-primary focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    />
  );
}
