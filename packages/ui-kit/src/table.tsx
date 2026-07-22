import type { ComponentPropsWithRef, KeyboardEvent, MouseEvent } from 'react';

import { cn } from './lib/cn.ts';

export function Table({ className, ...props }: ComponentPropsWithRef<'table'>) {
  return (
    <div className="w-full overflow-x-auto">
      <table
        data-slot="table"
        className={cn('w-full caption-bottom border-collapse text-sm', className)}
        {...props}
      />
    </div>
  );
}

export function TableHeader({ className, ...props }: ComponentPropsWithRef<'thead'>) {
  return (
    <thead
      data-slot="table-header"
      className={cn('[&_tr]:border-b [&_tr]:border-border', className)}
      {...props}
    />
  );
}

export function TableBody({ className, ...props }: ComponentPropsWithRef<'tbody'>) {
  return (
    <tbody
      data-slot="table-body"
      className={cn('[&_tr:last-child]:border-0', className)}
      {...props}
    />
  );
}

export function TableRow({
  className,
  onClick,
  onKeyDown,
  tabIndex,
  role,
  ...props
}: ComponentPropsWithRef<'tr'>) {
  // A row that carries an onClick is a navigation affordance (e.g. "open this
  // item's detail"), not a plain data row — give it the keyboard/AT support a
  // clickable row needs: focusable, announced as actionable, and Enter/Space
  // activatable. Rows without onClick are untouched.
  const isInteractive = typeof onClick === 'function';

  function handleKeyDown(event: KeyboardEvent<HTMLTableRowElement>) {
    onKeyDown?.(event);
    // Only treat Enter/Space as "activate the row" when the row itself is the
    // event target — a focusable control inside the row (e.g. an Expand
    // button) has already handled its own keydown/click by the time it would
    // bubble here, so this must not double-fire the row's action.
    if (
      !isInteractive ||
      event.defaultPrevented ||
      event.target !== event.currentTarget ||
      (event.key !== 'Enter' && event.key !== ' ')
    ) {
      return;
    }
    event.preventDefault();
    onClick(event as unknown as MouseEvent<HTMLTableRowElement>);
  }

  return (
    <tr
      data-slot="table-row"
      role={isInteractive ? (role ?? 'button') : role}
      tabIndex={isInteractive ? (tabIndex ?? 0) : tabIndex}
      onClick={onClick}
      onKeyDown={isInteractive ? handleKeyDown : onKeyDown}
      className={cn(
        'border-b border-text/6 transition-colors',
        isInteractive &&
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary/40',
        className,
      )}
      {...props}
    />
  );
}

export function TableHead({ scope = 'col', className, ...props }: ComponentPropsWithRef<'th'>) {
  return (
    <th
      data-slot="table-head"
      scope={scope}
      className={cn(
        'px-3 pb-3 text-left align-middle text-label font-semibold uppercase tracking-wider text-text-3',
        className,
      )}
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: ComponentPropsWithRef<'td'>) {
  return (
    <td data-slot="table-cell" className={cn('px-3 py-2 align-middle', className)} {...props} />
  );
}
