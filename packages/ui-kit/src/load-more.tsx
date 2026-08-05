import { type ComponentPropsWithRef } from 'react';

import { Button, type ButtonProps } from './button.tsx';
import { cn } from './lib/cn.ts';

/**
 * Cursor pagination footer: a "Load more" button plus a status line.
 *
 * Deliberately not numbered pages. The lists that use this are keyset-paged
 * (see the store's cursor reads), so page N is only reachable by walking pages
 * 1..N — there is no offset to jump to. It is also append-in-place, which keeps
 * scroll position by construction and creates no history entry, so a reader who
 * has walked four pages does not lose them by pressing Back.
 *
 * The status line is `aria-live="polite"`: appending rows below the viewport is
 * invisible to a screen reader otherwise.
 */
export function LoadMore({ className, ...props }: ComponentPropsWithRef<'div'>) {
  return (
    <div
      data-slot="load-more"
      className={cn('flex flex-col items-center gap-2 py-4', className)}
      {...props}
    />
  );
}

export function LoadMoreButton({
  loading = false,
  children,
  disabled,
  ...props
}: ButtonProps & { loading?: boolean }) {
  return (
    <Button
      data-slot="load-more-button"
      variant="outline"
      tone="neutral"
      size="sm"
      disabled={disabled ?? loading}
      {...props}
    >
      {loading && (
        <svg
          aria-hidden
          focusable={false}
          viewBox="0 0 16 16"
          className="size-3.5 animate-spin"
          fill="none"
        >
          <circle cx="8" cy="8" r="6" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2" />
          <path
            d="M14 8a6 6 0 0 0-6-6"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      )}
      {children ?? (loading ? 'Loading…' : 'Load more')}
    </Button>
  );
}

export function LoadMoreStatus({ className, ...props }: ComponentPropsWithRef<'p'>) {
  return (
    <p
      data-slot="load-more-status"
      aria-live="polite"
      className={cn('text-xs text-text-3', className)}
      {...props}
    />
  );
}
