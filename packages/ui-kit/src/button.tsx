import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { type ButtonHTMLAttributes, type Ref } from 'react';

import { cn } from './lib/cn.ts';

// Two independent axes: `variant` is the fill style, `tone` is the color. Their
// combinations are resolved by `compoundVariants` — e.g. a primary ghost button
// is `<Button variant="ghost" tone="primary" />`.
const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg font-medium transition-colors cursor-pointer disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        solid: '',
        outline: 'border',
        ghost: '',
      },
      tone: {
        primary: '',
        neutral: '',
        danger: '',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-9 px-4 text-sm',
        icon: 'size-9',
      },
    },
    compoundVariants: [
      // solid
      {
        variant: 'solid',
        tone: 'primary',
        class: 'bg-primary text-text-inv hover:bg-primary-hover',
      },
      { variant: 'solid', tone: 'neutral', class: 'bg-surface-3 text-text hover:bg-border-strong' },
      {
        variant: 'solid',
        tone: 'danger',
        class: 'bg-sev-critical text-text-inv hover:bg-sev-critical-hover',
      },
      // outline
      {
        variant: 'outline',
        tone: 'primary',
        class: 'border-primary text-primary hover:bg-primary-tint',
      },
      {
        variant: 'outline',
        tone: 'neutral',
        class: 'border-border bg-surface text-text hover:bg-surface-2',
      },
      {
        variant: 'outline',
        tone: 'danger',
        class: 'border-sev-critical text-sev-critical hover:bg-sev-critical-fill',
      },
      // ghost
      { variant: 'ghost', tone: 'primary', class: 'text-primary hover:bg-primary-tint' },
      {
        variant: 'ghost',
        tone: 'neutral',
        class: 'text-text-2 hover:bg-surface-2 hover:text-text',
      },
      {
        variant: 'ghost',
        tone: 'danger',
        class: 'text-sev-critical hover:bg-sev-critical-fill',
      },
    ],
    defaultVariants: { variant: 'solid', tone: 'neutral', size: 'md' },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  /** Render as the single child element instead of a `<button>` (Radix Slot). */
  asChild?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({
  className,
  variant,
  tone,
  size,
  asChild = false,
  type,
  ...props
}: ButtonProps) {
  const Comp = asChild ? Slot : 'button';
  return (
    <Comp
      className={cn(buttonVariants({ variant, tone, size }), className)}
      // Slot forwards to whatever element is passed; only set `type` on a real button.
      {...(asChild ? {} : { type: type ?? 'button' })}
      {...props}
    />
  );
}
