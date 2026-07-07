'use client';
// Multi-select harness filter. Empty selection == "All harnesses"; selecting every
// harness collapses back to All. Built on the ui-kit DropdownMenu (Radix) — the
// checkbox items keep the menu open on toggle via preventDefault.
import {
  Badge,
  cn,
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@akasecurity/ui-kit';

import { ChevronDownIcon, TerminalIcon } from '../shared/icons.tsx';
import { PROVIDERS } from '../shared/Provider.tsx';
import { HARNESS_IDS } from './meta.ts';
import type { HarnessId } from './types.ts';

export function HarnessSelect({
  value,
  onChange,
}: {
  value: HarnessId[];
  onChange: (next: HarnessId[]) => void;
}) {
  const all = value.length === 0;
  const first = value[0];
  const label = all
    ? 'All harnesses'
    : value.length === 1 && first
      ? PROVIDERS[first].label
      : `${String(value.length)} harnesses`;

  function toggle(id: HarnessId) {
    const next = value.includes(id) ? value.filter((x) => x !== id) : [...value, id];
    // Everything selected individually reads the same as "All".
    onChange(next.length === HARNESS_IDS.length ? [] : next);
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          'group flex h-8.5 w-full items-center gap-2 rounded-lg border bg-surface px-2.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
          all ? 'border-border' : 'border-primary',
        )}
      >
        <TerminalIcon
          aria-hidden
          focusable={false}
          className={cn('size-3.5 shrink-0', all ? 'text-text-3' : 'text-primary')}
        />
        <span className="flex-1 text-left font-medium text-text">{label}</span>
        {!all && (
          <Badge variant="primary" className="px-1.5 py-0 text-label bg-surface">
            {value.length}
          </Badge>
        )}
        <ChevronDownIcon
          aria-hidden
          focusable={false}
          className="size-3.5 shrink-0 text-text-3 transition-transform group-data-[state=open]:rotate-180"
        />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-(--radix-dropdown-menu-trigger-width)">
        <DropdownMenuCheckboxItem
          checked={all}
          onCheckedChange={() => {
            onChange([]);
          }}
          onSelect={(e) => {
            e.preventDefault();
          }}
        >
          All harnesses
        </DropdownMenuCheckboxItem>
        <DropdownMenuSeparator />
        {HARNESS_IDS.map((id) => (
          <DropdownMenuCheckboxItem
            key={id}
            checked={value.includes(id)}
            onCheckedChange={() => {
              toggle(id);
            }}
            onSelect={(e) => {
              e.preventDefault();
            }}
          >
            <span className="flex items-center gap-2">
              <span
                className="size-2 shrink-0 rounded-xs"
                style={{ background: PROVIDERS[id].color }}
              />
              {PROVIDERS[id].label}
            </span>
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
