import type { ComponentPropsWithRef } from 'react';

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

export function TableRow({ className, ...props }: ComponentPropsWithRef<'tr'>) {
  return (
    <tr
      data-slot="table-row"
      className={cn('border-b border-text/6 transition-colors', className)}
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
