import * as TabsPrimitive from '@radix-ui/react-tabs';
import { type ComponentPropsWithRef } from 'react';

import { cn } from './lib/cn.ts';

/**
 * Tabbed panels built on @radix-ui/react-tabs — roving-focus keyboard
 * navigation between triggers, and only the active panel mounted. Compound
 * API:
 *
 *   <Tabs defaultValue="a">
 *     <TabsList>
 *       <TabsTrigger value="a">A</TabsTrigger>
 *       <TabsTrigger value="b">B</TabsTrigger>
 *     </TabsList>
 *     <TabsContent value="a">…panel A…</TabsContent>
 *     <TabsContent value="b">…panel B…</TabsContent>
 *   </Tabs>
 */
export const Tabs = TabsPrimitive.Root;

export type TabsListProps = ComponentPropsWithRef<typeof TabsPrimitive.List>;

export function TabsList({ className, ...props }: TabsListProps) {
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      className={cn(
        'inline-flex items-center gap-0.5 rounded-lg border border-border bg-surface-2 p-0.5',
        className,
      )}
      {...props}
    />
  );
}

export type TabsTriggerProps = ComponentPropsWithRef<typeof TabsPrimitive.Trigger>;

export function TabsTrigger({ className, ...props }: TabsTriggerProps) {
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(
        'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-xs font-semibold text-text-3 transition-colors cursor-pointer',
        'hover:text-text-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        'data-[state=active]:bg-surface data-[state=active]:text-text data-[state=active]:shadow-sm',
        '[&_svg]:size-4 [&_svg]:shrink-0',
        className,
      )}
      {...props}
    />
  );
}

export type TabsContentProps = ComponentPropsWithRef<typeof TabsPrimitive.Content>;

export function TabsContent({ className, ...props }: TabsContentProps) {
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      className={cn('focus-visible:outline-none', className)}
      {...props}
    />
  );
}
