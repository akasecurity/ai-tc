// Small presentational atoms for the Activity views. Pure/props-driven — no state.
import type { SessionStatus } from '@akasecurity/schema';
import { Badge, cn } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import type { IconComponent } from '../lib/icons.ts';
import { STATUS_META, TOOL_ICON_FALLBACK, TOOL_META } from './meta.ts';

/** A status dot. `active` renders a pulsing "live" ring; others a solid token dot. */
export function StatusDot({ status }: { status: SessionStatus }) {
  if (status === 'active') {
    return (
      <span className="relative flex size-2 shrink-0" title="Live">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-75" />
        <span className="relative inline-flex size-2 rounded-full bg-ok" />
      </span>
    );
  }
  return <span className={cn('size-1.5 shrink-0 rounded-full', STATUS_META[status].dot)} />;
}

/** Session status pill: a leading dot + label, tinted by status. */
export function SessionStatusBadge({ status }: { status: SessionStatus }) {
  const m = STATUS_META[status];
  return (
    <Badge variant={m.badge} className="h-6 gap-1.5">
      <StatusDot status={status} />
      {m.label}
    </Badge>
  );
}

/** A muted icon + value metric (duration, turns, findings…) on a session row. */
export function Metric({ icon: Icon, children }: { icon: IconComponent; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-xs text-text-3">
      <Icon aria-hidden focusable={false} className="size-3" />
      {children}
    </span>
  );
}

/** A tool-call chip: glyph + tool name + tabular count. */
export function ToolChip({ name, n }: { name: string; n: number }) {
  const Icon = TOOL_META[name] ?? TOOL_ICON_FALLBACK;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-2 py-0.5 px-2 text-xs font-semibold text-text-2">
      <Icon aria-hidden focusable={false} className="size-3 text-text-3" />
      {name}
      <span className="tabular-nums text-text">{n}</span>
    </span>
  );
}

/** A wrap of small chips for a multi-valued meta field (branches, models). */
export function MetaChips({ items, mono = false }: { items: string[]; mono?: boolean }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <span
          key={item}
          className={cn(
            'rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-xs text-text',
            mono && 'font-mono',
          )}
        >
          {item}
        </span>
      ))}
    </div>
  );
}
