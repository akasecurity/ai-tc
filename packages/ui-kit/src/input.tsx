import type { ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * A text input primitive. Styles a native `<input>` with the design tokens
 * (surface fill, border, primary focus ring) so forms across the dashboards
 * share one field look. `ref` flows through as a regular prop (React 19).
 */
export function Input({ className, type = 'text', ...props }: ComponentPropsWithRef<'input'>) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        'h-9 w-full rounded-lg border border-border bg-surface px-3 text-sm text-text',
        'placeholder:text-text-3 transition-colors',
        'focus:border-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
    />
  );
}
