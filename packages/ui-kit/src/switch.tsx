import * as SwitchPrimitive from '@radix-ui/react-switch';
import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * On/off toggle built on @radix-ui/react-switch. Controlled via `checked` +
 * `onCheckedChange`. The thumb slides and the track turns `ok` when on.
 *
 *   <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Enable" />
 */
export type SwitchProps = ComponentPropsWithRef<typeof SwitchPrimitive.Root>;

export function Switch({ className, ...props }: SwitchProps) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        'peer inline-flex h-5.5 w-9.5 shrink-0 cursor-pointer items-center rounded-full p-0.5 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/40 disabled:cursor-not-allowed disabled:opacity-50',
        'data-[state=checked]:bg-ok data-[state=unchecked]:bg-border-strong',
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block size-4.5 rounded-full bg-white shadow-sm transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0"
      />
    </SwitchPrimitive.Root>
  );
}
