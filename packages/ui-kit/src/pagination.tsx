import { type ComponentPropsWithRef } from 'react';

import { Button, type ButtonProps } from './button.tsx';
import { cn } from './lib/cn.ts';

/**
 * Discrete-page footer: Previous/Next buttons plus a status line.
 *
 * For a list whose caller pages through discrete chunks instead of
 * accumulating everything fetched so far. Stepping only — no numbered page
 * links — because the lists this backs are keyset-paged: there is no offset
 * to jump to, only "the page after this cursor." The caller owns its page
 * cache and cursor history, so Previous is expected to replay an
 * already-fetched page rather than refetch.
 */
export function Pagination({ className, ...props }: ComponentPropsWithRef<'nav'>) {
  return (
    <nav
      data-slot="pagination"
      role="navigation"
      aria-label="Pagination"
      className={cn('flex items-center justify-center gap-3 py-4', className)}
      {...props}
    />
  );
}

export function PaginationPrevious({ children, ...props }: ButtonProps) {
  return (
    <Button data-slot="pagination-previous" variant="outline" tone="neutral" size="sm" {...props}>
      <ChevronLeftIcon aria-hidden focusable={false} />
      {children ?? 'Previous'}
    </Button>
  );
}

export function PaginationNext({
  loading = false,
  children,
  disabled = false,
  ...props
}: ButtonProps & { loading?: boolean }) {
  return (
    <Button
      data-slot="pagination-next"
      variant="outline"
      tone="neutral"
      size="sm"
      disabled={disabled || loading}
      {...props}
    >
      {children ?? (loading ? 'Loading…' : 'Next')}
      {loading ? (
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
      ) : (
        <ChevronRightIcon aria-hidden focusable={false} />
      )}
    </Button>
  );
}

export function PaginationStatus({ className, ...props }: ComponentPropsWithRef<'p'>) {
  return (
    <p
      data-slot="pagination-status"
      aria-live="polite"
      className={cn('text-xs text-text-3', className)}
      {...props}
    />
  );
}

function ChevronLeftIcon(props: ComponentPropsWithRef<'svg'>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="m15 6-6 6 6 6" />
    </svg>
  );
}

function ChevronRightIcon(props: ComponentPropsWithRef<'svg'>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="m9 6 6 6-6 6" />
    </svg>
  );
}
